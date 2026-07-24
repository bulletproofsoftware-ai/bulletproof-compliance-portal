"""WI-17 Security middleware tests."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from portal.main import create_app
from portal.middleware.audit_guard import (
    AuditWriteForbidden,
    install_audit_guard,
    query_touches_audit_table,
)
from portal.security.behavior_hook import anomaly_score


# ─── Security headers ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_all_security_headers_present_internal() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.get("/healthz")
    expected = {
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy",
    }
    for h in expected:
        assert h in r.headers, f"missing header {h}"


@pytest.mark.asyncio
async def test_csp_blocks_inline_scripts() -> None:
    """CSP must NOT contain `'unsafe-inline'` for scripts (only for styles)."""
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.get("/healthz")
    csp = r.headers["Content-Security-Policy"]
    # script-src must NOT have unsafe-inline
    script_section = next(p for p in csp.split(";") if "script-src" in p)
    assert "'unsafe-inline'" not in script_section


# ─── CORS — wildcard rejected ────────────────────────────────────────────────


def test_cors_rejects_wildcard() -> None:
    from portal.middleware.cors import build_cors_middleware

    with pytest.raises(ValueError):
        build_cors_middleware(allowed_origins=["*"])


def test_cors_accepts_explicit_origin() -> None:
    from portal.middleware.cors import build_cors_middleware

    mw, kwargs = build_cors_middleware(allowed_origins=["https://portal.internal"])
    assert "*" not in kwargs["allow_origins"]
    assert "https://portal.internal" in kwargs["allow_origins"]


# ─── Rate limiting (smoke test — slowapi works inside the app) ───────────────


@pytest.mark.asyncio
async def test_app_starts_with_rate_limiter() -> None:
    """We don't burst-fire here (slow), just verify the limiter is installed."""
    app = create_app(mode="internal")
    assert app.state.limiter is not None


# ─── CSRF — unsafe methods blocked without token ─────────────────────────────


@pytest.mark.asyncio
async def test_csrf_blocks_post_without_token() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.post("/some-route", json={"x": 1})
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "csrf_invalid"


@pytest.mark.asyncio
async def test_csrf_token_issued_on_get() -> None:
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        r = await client.get("/healthz")
    # CSRF cookie set on GET when not present
    assert "csrf" in r.cookies or any("csrf=" in s for s in r.headers.get_list("set-cookie"))


@pytest.mark.asyncio
async def test_csrf_callback_path_exempt() -> None:
    """OIDC callback must be exempt — IdP can't carry CSRF tokens."""
    app = create_app(mode="internal")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        # POST to the exempt path (still 4xx for missing flow, but NOT 403 csrf_invalid)
        r = await client.post("/auth/callback")
    body = r.json()
    assert body.get("code") != "csrf_invalid"


# ─── Audit logging excludes health ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_excludes_health_paths() -> None:
    """Health endpoints must NOT trigger audit middleware (per WI-17)."""
    from portal.middleware.audit import AuditLoggingMiddleware

    mw = AuditLoggingMiddleware(app=None, forward_to_compliance=False)
    assert mw._is_excluded("/healthz")
    assert mw._is_excluded("/readyz")
    assert mw._is_excluded("/static/css/portal.css")
    assert not mw._is_excluded("/auth/login")


# ─── Audit guard (REQ-CPL-039) ───────────────────────────────────────────────


def test_audit_guard_pattern_detects_insert() -> None:
    assert query_touches_audit_table("INSERT INTO immutable_audit_events (a) VALUES (1)")
    assert query_touches_audit_table("insert into immutable_audit_events values (1)")
    assert query_touches_audit_table('INSERT INTO public."immutable_audit_events" (x) VALUES (1)')


def test_audit_guard_pattern_detects_update_delete_truncate() -> None:
    assert query_touches_audit_table("UPDATE immutable_audit_events SET x=1")
    assert query_touches_audit_table("DELETE FROM immutable_audit_events")
    assert query_touches_audit_table("TRUNCATE immutable_audit_events")


def test_audit_guard_pattern_ignores_safe_queries() -> None:
    # SELECT is allowed — read-only access by the portal is fine
    assert not query_touches_audit_table("SELECT * FROM immutable_audit_events")
    # Different table is allowed
    assert not query_touches_audit_table("INSERT INTO some_other_table VALUES (1)")
    # Empty/None
    assert not query_touches_audit_table("")
    assert not query_touches_audit_table(None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_audit_guard_runtime_blocks_insert() -> None:
    class _FakePool:
        async def execute(self, query, *a, **kw):
            return ("EXECUTED", query)

        async def executemany(self, query, *a, **kw):
            return ("EXECUTED_MANY", query)

    pool = install_audit_guard(_FakePool())
    # Allowed
    assert (await pool.execute("SELECT 1")) == ("EXECUTED", "SELECT 1")
    # Blocked
    with pytest.raises(AuditWriteForbidden):
        await pool.execute("INSERT INTO immutable_audit_events (x) VALUES (1)")
    with pytest.raises(AuditWriteForbidden):
        await pool.executemany("UPDATE immutable_audit_events SET x=1", [(1,)])


def test_audit_guard_idempotent() -> None:
    class _FakePool:
        async def execute(self, q, *a, **k):
            return q

    pool = _FakePool()
    install_audit_guard(pool)
    install_audit_guard(pool)  # second call is a no-op
    assert pool._audit_guard_installed is True


# ─── Behavior hook ───────────────────────────────────────────────────────────


def test_anomaly_score_increases_with_status() -> None:
    assert anomaly_score(status=200, user_agent="Mozilla/5.0 normal") == 0.0
    assert anomaly_score(status=401, user_agent="Mozilla/5.0 normal") > 0.0
    assert anomaly_score(status=500, user_agent="Mozilla/5.0 normal") > anomaly_score(
        status=401, user_agent="Mozilla/5.0 normal"
    )


def test_anomaly_score_flags_known_scanner_ua() -> None:
    score = anomaly_score(status=200, user_agent="sqlmap/1.7")
    assert score >= 0.5
