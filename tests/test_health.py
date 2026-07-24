"""Health & readiness endpoint tests."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from portal.main import create_app


@pytest.mark.asyncio
async def test_healthz_returns_200() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        r = await client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_request_id_echoed() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        r = await client.get("/healthz", headers={"X-Request-ID": "rid-abc-123"})
    assert r.headers.get("x-request-id") == "rid-abc-123"


@pytest.mark.asyncio
async def test_security_headers_present() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        r = await client.get("/healthz")
    assert "Content-Security-Policy" in r.headers
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "Strict-Transport-Security" in r.headers


@pytest.mark.asyncio
async def test_readyz_no_compliance_client_ok() -> None:
    """When no compliance client is wired (test env), readyz returns 200."""
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        r = await client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["compliance_api"] is True
    assert "compliance_circuit" in body
