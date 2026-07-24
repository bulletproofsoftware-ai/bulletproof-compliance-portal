"""WI-03 Compliance API client tests."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from shared.api_client import (
    AuthenticationError,
    ComplianceClient,
    ConflictError,
    NotFoundError,
    ScopeViolationError,
    ServiceUnavailableError,
    UnexpectedRedirectError,
)
from shared.api_client.circuit_breaker import CircuitBreaker, CircuitBreakerState

BASE = "https://compliance.test/api/v1/compliance"


def _client(**overrides) -> ComplianceClient:
    kwargs = dict(
        base_url=BASE,
        token="test-token",
        timeout_s=2.0,
        user_sub="alice",
        request_id="rid-1",
    )
    kwargs.update(overrides)
    return ComplianceClient(**kwargs)


# ─── AMD-25 follow_redirects=False ───────────────────────────────────────────


def test_client_constructed_with_follow_redirects_false() -> None:
    c = _client()
    assert c.follow_redirects is False


@pytest.mark.asyncio
async def test_client_refuses_to_follow_redirect() -> None:
    """AMD-25 — server returns 302; client raises UnexpectedRedirectError."""
    async with respx.mock(base_url=BASE) as mock:
        mock.get("/audit/events").respond(
            status_code=302, headers={"Location": "http://internal-host/leak"}
        )
        async with _client() as c:
            with pytest.raises(UnexpectedRedirectError) as info:
                await c.list_audit_events()
        assert info.value.code == "unexpected_redirect"
        assert "internal-host" in info.value.message


# ─── On-behalf-of + request id headers ───────────────────────────────────────


@pytest.mark.asyncio
async def test_on_behalf_of_header_set() -> None:
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events").respond(json={"items": []})
        async with _client(user_sub="alice") as c:
            await c.list_audit_events()
        sent = route.calls[0].request
        assert sent.headers["x-on-behalf-of"] == "alice"
        assert sent.headers["x-request-id"] == "rid-1"


@pytest.mark.asyncio
async def test_authorization_header_set() -> None:
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events").respond(json={"items": []})
        async with _client(token="abc-123") as c:
            await c.list_audit_events()
        assert route.calls[0].request.headers["authorization"] == "Bearer abc-123"


# ─── Auditor scope injection ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_auditor_scope_injected_on_get() -> None:
    scope = {
        "engagement_id": "eng-1",
        "date_range_start": "2026-01-01T00:00:00Z",
        "date_range_end": "2026-04-01T00:00:00Z",
        "allowed_artifact_types": ["audit_event", "evidence_package"],
    }
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events").respond(json={"items": []})
        async with _client(auditor_scope=scope) as c:
            await c.list_audit_events()
        url = route.calls[0].request.url
        assert "engagement_id=eng-1" in str(url)
        assert "from=" in str(url)
        assert "to=" in str(url)
        assert "artifact_types=" in str(url)


# ─── Error mapping ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_404_raises_not_found() -> None:
    async with respx.mock(base_url=BASE) as mock:
        mock.get("/audit/events/abc").respond(status_code=404, json={"code": "not_found", "message": "x"})
        async with _client() as c:
            with pytest.raises(NotFoundError):
                await c.get_audit_event("abc")


@pytest.mark.asyncio
async def test_409_raises_conflict() -> None:
    async with respx.mock(base_url=BASE) as mock:
        mock.post("/audit/events").respond(status_code=409, json={"code": "sod_violation", "message": "x"})
        async with _client() as c:
            with pytest.raises(ConflictError):
                await c.record_audit_event(audit_type="x")


@pytest.mark.asyncio
async def test_403_scope_violation_raises_typed() -> None:
    async with respx.mock(base_url=BASE) as mock:
        mock.get("/audit/events").respond(
            status_code=403, json={"code": "scope_violation", "message": "out of scope"}
        )
        async with _client() as c:
            with pytest.raises(ScopeViolationError):
                await c.list_audit_events()


@pytest.mark.asyncio
async def test_401_raises_authentication() -> None:
    async with respx.mock(base_url=BASE) as mock:
        mock.get("/audit/events").respond(status_code=401, json={"code": "unauth", "message": "x"})
        async with _client() as c:
            with pytest.raises(AuthenticationError):
                await c.list_audit_events()


# ─── Retry / circuit breaker ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_500_retries_then_fails() -> None:
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events").respond(status_code=500, json={"code": "x"})
        async with _client() as c:
            with pytest.raises(ServiceUnavailableError):
                await c.list_audit_events()
        # Three attempts on idempotent GETs
        assert route.call_count == 3


@pytest.mark.asyncio
async def test_500_then_200_succeeds_after_retry() -> None:
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events")
        route.side_effect = [
            httpx.Response(500, json={"code": "x"}),
            httpx.Response(200, json={"items": []}),
        ]
        async with _client() as c:
            out = await c.list_audit_events()
        assert out.items == []


@pytest.mark.asyncio
async def test_4xx_does_not_retry() -> None:
    async with respx.mock(base_url=BASE) as mock:
        route = mock.get("/audit/events/abc").respond(status_code=400, json={"code": "x"})
        async with _client() as c:
            with pytest.raises(Exception):
                await c.get_audit_event("abc")
        assert route.call_count == 1


@pytest.mark.asyncio
async def test_circuit_opens_after_threshold() -> None:
    cb = CircuitBreaker(failure_threshold=2, window_s=10, cooldown_s=60)
    # Exhaust failures via direct calls (faster than HTTP setup)
    await cb.record_failure()
    await cb.record_failure()
    assert cb.state is CircuitBreakerState.OPEN
    assert (await cb.can_request()) is False  # fail fast


@pytest.mark.asyncio
async def test_circuit_half_open_after_cooldown() -> None:
    cb = CircuitBreaker(failure_threshold=1, window_s=10, cooldown_s=0.05)
    await cb.record_failure()
    assert cb.state is CircuitBreakerState.OPEN
    await asyncio.sleep(0.06)
    can = await cb.can_request()
    assert can is True
    assert cb.state is CircuitBreakerState.HALF_OPEN
    # Half-open success closes circuit
    await cb.record_success()
    assert cb.state is CircuitBreakerState.CLOSED


@pytest.mark.asyncio
async def test_circuit_open_raises_service_unavailable_via_client() -> None:
    cb = CircuitBreaker(failure_threshold=1, window_s=10, cooldown_s=60)
    # Force open
    await cb.record_failure()
    async with _client(circuit_breaker=cb) as c:
        with pytest.raises(ServiceUnavailableError) as info:
            await c.list_audit_events()
    assert info.value.code == "circuit_open"


# ─── mTLS configuration (AMD-10) ─────────────────────────────────────────────


def test_mtls_paths_passed_through_to_httpx() -> None:
    """AMD-10 plumbing — the client's `_http` is built with the ca_bundle,
    cert, and key. We don't load real PEMs (that's an integration concern);
    we assert only that the values flow into httpx's SSLConfig.

    Strategy: read the constructed AsyncClient's verify/cert attributes back
    via the public httpx API. httpx stores `verify` on each transport's pool;
    we inspect the constructor inputs by patching httpx.AsyncClient.
    """
    captured: dict = {}
    real_cls = httpx.AsyncClient

    def _spy(*args, **kwargs):
        captured.update(kwargs)
        # Return a real client built without the cert flags so SSL load works
        kwargs.pop("verify", None)
        kwargs.pop("cert", None)
        return real_cls(*args, **kwargs)

    httpx.AsyncClient = _spy  # type: ignore[assignment]
    try:
        _client(
            ca_bundle="/tmp/fake-ca.crt",
            client_cert="/tmp/fake-client.crt",
            client_key="/tmp/fake-client.key",
        )
        assert captured.get("follow_redirects") is False  # AMD-25
        assert captured.get("verify") == "/tmp/fake-ca.crt"
        assert captured.get("cert") == ("/tmp/fake-client.crt", "/tmp/fake-client.key")
    finally:
        httpx.AsyncClient = real_cls  # type: ignore[assignment]
