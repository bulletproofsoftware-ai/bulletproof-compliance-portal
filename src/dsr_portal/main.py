"""Public DSR Portal — FastAPI app factory.

Architecturally separate from the internal portal. All identity-proof file
uploads stream directly to the compliance service; nothing persists in this
container.

Middleware stack (registered REVERSE — outermost runs first inbound):

    1. ForwardedHeaderMiddleware  (trust proxies)
    2. RequestIDMiddleware
    3. SecurityHeadersMiddleware  (CSP, HSTS, etc — strict, public mode)
    4. SlowAPIMiddleware          (100 req/min/IP global)
    5. PublicBodySizeLimit        (AMD-11 — 5MB cap, 413 if exceeded)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from portal.config import Settings, get_settings
from portal.logging import configure_logging, get_logger
from portal.middleware import (
    ForwardedHeaderMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    register_rate_limit,
)
from shared.api_client import ComplianceClient

from .auth.token import PublicTokenManager
from .malware_scan import MAX_BYTES
from .routers import submit as submit_router_module

logger = get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class PublicBodySizeLimitMiddleware(BaseHTTPMiddleware):
    """AMD-11 — enforce 5MB body cap before reaching route handlers.

    nginx fronts the public app with `client_max_body_size 8m` (5MB payload +
    headroom for multipart envelope). This middleware enforces the application
    cap of 5MB and returns 413 with a friendly response. nginx blocks anything
    above 8MB at the edge.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int = MAX_BYTES) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": "payload too large",
                            "max_bytes": self.max_bytes,
                            "code": "body_size_exceeded",
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)


def _public_token_secret(settings: Settings) -> str:
    """Public-portal token secret. MUST be different from session_secret.

    Production deployment sets `PUBLIC_TOKEN_SECRET` env var. For test/dev,
    we derive a separate secret from session_secret + a hardcoded namespace.
    """
    explicit = os.environ.get("PUBLIC_TOKEN_SECRET")
    if explicit:
        return explicit
    # Derive from session_secret with a constant suffix — distinct namespace.
    base = settings.session_secret.get_secret_value()
    return f"{base}::public-dsr-portal-v1"


def _settings_summary(settings: Settings) -> dict[str, Any]:
    return {
        "app_env": settings.app_env,
        "captcha_provider": settings.captcha_provider,
        "captcha_secret": settings.captcha_secret.get_secret_value()
        if settings.captcha_secret
        else "",
    }


def _default_compliance_client_factory(request: Request) -> ComplianceClient:
    """Build a ComplianceClient for the current public-portal request.

    Public-portal token is the SAME ComplianceAPI token by default in this
    foundation batch — production deployment provisions a SEPARATE token with
    capability ACL enforced server-side (AMD-05). The capability ACL is
    enforced client-side via TokenCapability checks on each route.
    """
    settings: Settings = request.app.state.settings
    return ComplianceClient(
        base_url=str(settings.compliance_api_base_url),
        token=settings.compliance_api_token.get_secret_value(),
        timeout_s=settings.compliance_api_timeout_s,
        ca_bundle=str(settings.compliance_api_ca_bundle)
        if settings.compliance_api_ca_bundle
        else None,
        client_cert=str(settings.compliance_api_client_cert)
        if settings.compliance_api_client_cert
        else None,
        client_key=str(settings.compliance_api_client_key)
        if settings.compliance_api_client_key
        else None,
        user_sub=None,  # public — no user context
        request_id=getattr(request.state, "request_id", None),
    )


def create_public_app(
    *,
    settings: Settings | None = None,
    compliance_client_factory: Callable[[Request], ComplianceClient] | None = None,
    public_token_mgr: PublicTokenManager | None = None,
) -> FastAPI:
    """Construct the public DSR portal FastAPI app."""
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_output=settings.app_env != "development")

    app = FastAPI(
        title="Public DSR Portal",
        version="0.1.0",
        # NOT mounted: /docs, /redoc, /openapi.json (per WI-09 spec)
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # ── App state ────────────────────────────────────────────────────────────
    app.state.settings = settings
    app.state.settings_summary = _settings_summary(settings)
    app.state.templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    app.state.compliance_client_factory = (
        compliance_client_factory or _default_compliance_client_factory
    )
    app.state.public_token_mgr = public_token_mgr or PublicTokenManager(
        secret=_public_token_secret(settings)
    )

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(submit_router_module.router)

    # ── Rate limit (100 req/min/IP global; per-route overrides via decorators
    #    available, but global default is sufficient for AMD-11 compliance) ──
    register_rate_limit(
        app,
        mode="public",
        public_per_minute=settings.public_rate_limit_per_min,
    )

    # ── Middleware ───────────────────────────────────────────────────────────
    app.add_middleware(SlowAPIMiddleware)
    app.add_middleware(PublicBodySizeLimitMiddleware, max_bytes=MAX_BYTES)
    app.add_middleware(SecurityHeadersMiddleware, mode="public")
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(
        ForwardedHeaderMiddleware, trusted_cidrs=settings.trusted_proxy_cidrs
    )

    @app.exception_handler(404)
    async def _not_found(request: Request, exc: Any) -> Response:
        # Generic 404 — don't leak route shape.
        return PlainTextResponse(
            "Not Found", status_code=404, headers={"X-Content-Type-Options": "nosniff"}
        )

    return app


# ── Default uvicorn target (WI-18) ───────────────────────────────────────────
# Uvicorn discovers `dsr_portal.main:app` for production container ENTRYPOINT.
# Construction is deferred to module import time, identical to portal.main:app.
app: FastAPI = create_public_app()


__all__ = ["create_public_app", "app"]
