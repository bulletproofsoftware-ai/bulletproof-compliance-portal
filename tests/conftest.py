"""Pytest fixtures shared by all test modules."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator

import pytest

# Ensure src/ is on sys.path BEFORE any portal imports below.
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Force a known session secret long enough to pass the validator.
os.environ.setdefault(
    "SESSION_SECRET",
    "test-secret-deterministic-32-bytes-of-key-material-1234567890",
)
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("REDIS_URL", "")  # use in-memory store
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("OIDC_ISSUER", "https://oidc.test/")
os.environ.setdefault("OIDC_REDIRECT_URI", "http://localhost/auth/callback")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost")
os.environ.setdefault(
    "COMPLIANCE_API_BASE_URL", "https://compliance.test/api/v1/compliance"
)
os.environ.setdefault("COMPLIANCE_API_TOKEN", "test-token")

from portal.auth.models import AuditorScope, Role, User  # noqa: E402
from portal.auth.session import InMemorySessionStore  # noqa: E402
from portal.config import reset_settings_cache  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():  # type: ignore[no-untyped-def]
    """Use a single asyncio loop for the whole session (pytest-asyncio compat)."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def _reset_settings():
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture()
def session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


def _build_user(
    *,
    sub: str = "user-1",
    roles: list[Role] | None = None,
    mfa_age_s: int | None = 0,
    auditor_scope: AuditorScope | None = None,
) -> User:
    now = datetime.now(timezone.utc)
    mfa_at = (now - timedelta(seconds=mfa_age_s)) if mfa_age_s is not None else None
    return User(
        sub=sub,
        email=f"{sub}@example.com",
        name=f"User {sub}",
        roles=roles or [Role.VIEWER],
        auditor_scope=auditor_scope,
        mfa_at=mfa_at,
        session_id="placeholder",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )


@pytest.fixture()
def make_user():
    return _build_user


@pytest.fixture()
async def populated_session(
    session_store: InMemorySessionStore, make_user
) -> AsyncIterator[tuple[InMemorySessionStore, str, User]]:
    user = make_user(roles=[Role.COMPLIANCE_OFFICER])
    sid = await session_store.create(
        payload={"user": user.model_dump(mode="json")}, ttl_s=3600
    )
    user_with_sid = user.model_copy(update={"session_id": sid})
    await session_store.set(
        sid, {"user": user_with_sid.model_dump(mode="json")}, ttl_s=3600
    )
    yield session_store, sid, user_with_sid


# ─── Router-level test scaffolding (WI-04..07) ─────────────────────────────


@pytest.fixture()
def fake_compliance_client():
    """Fresh in-memory FakeComplianceClient per test."""
    from tests._fakes import FakeComplianceClient

    return FakeComplianceClient()


@pytest.fixture()
def build_router_app(fake_compliance_client):
    """Construct a minimal FastAPI app with a chosen router and a hard-coded
    `current_user`, with the ComplianceClient dependency overridden to the
    in-memory fake.

    Usage:
        app = build_router_app(audit_router_module.router, user)
        client = TestClient(app)
    """
    from fastapi import FastAPI

    from portal.auth.rbac import current_user as current_user_dep
    from portal.dependencies import get_compliance_client

    def _build(router, user, *, extra_routers=()):  # type: ignore[no-untyped-def]
        app = FastAPI()
        # Mirror what main.py wires for the export router (used by some tests).
        from portal.pdf.cache import PdfCache
        from portal.pdf.registry import get_default_registry
        from portal.pdf.service import PdfService

        app.state.pdf_cache = PdfCache()
        app.state.pdf_registry = get_default_registry()
        app.state.pdf_service = PdfService(cache=app.state.pdf_cache)
        app.include_router(router)
        for extra in extra_routers:
            app.include_router(extra)
        app.dependency_overrides[current_user_dep] = lambda: user
        app.dependency_overrides[get_compliance_client] = lambda: fake_compliance_client
        return app

    return _build
