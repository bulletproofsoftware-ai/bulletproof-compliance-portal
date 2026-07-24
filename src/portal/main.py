"""FastAPI application entrypoint and factory.

Implements WI-01 (skeleton) + wires WI-02 (auth), WI-17 (security middleware).
The factory accepts a `mode` so the same module backs both the internal portal
and the future public DSR portal (WI-09 will mount its own routes on the
public app via this factory).

Middleware registration order (WI-17 §"Middleware Registration Order"):

    1. ForwardedHeaderMiddleware
    2. RequestIDMiddleware
    3. SecurityHeadersMiddleware
    4. CORSMiddleware                   (Starlette built-in)
    5. SlowAPIMiddleware                (rate limit) — installed via register_rate_limit
    6. CsrfMiddleware
    7. AuditLoggingMiddleware
    8. BehaviorHookMiddleware

Note: Starlette runs middleware in REVERSE registration order (last-added
runs first on the inbound path). We register in REVERSE so the runtime order
matches the spec.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Literal

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.cors import CORSMiddleware

from .auth.csrf import CsrfTokenManager
from .auth.oidc import build_auth_router, build_oauth_client
from .auth.session import InMemorySessionStore, RedisSessionStore, SessionStore
from .config import Settings, get_settings
from .dependencies import get_compliance_client
from .logging import configure_logging, get_logger
from .middleware import (
    AuditLoggingMiddleware,
    CsrfMiddleware,
    ForwardedHeaderMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    build_cors_middleware,
    register_rate_limit,
)
from .pdf.cache import PdfCache
from .pdf.registry import get_default_registry
from .pdf.service import PdfService
from .routers import audit as audit_router_module
from .routers import auditor_admin as auditor_admin_router_module
from .routers import dashboards as dashboards_router_module
from .routers import dsr as dsr_router_module
from .routers import evidence as evidence_router_module
from .routers import export as export_router_module
from .routers import gates as gates_router_module
from .routers import health
from .routers import home as home_router_module
from .routers import incidents as incidents_router_module
from .routers import model_cards as model_cards_router_module
from .routers import outcomes as outcomes_router_module
from .routers import process_knowledge as process_knowledge_router_module
from .routers import project_docs as project_docs_router_module
from .routers import reports as reports_router_module
from .security import BehaviorHookMiddleware, register_exception_handlers

logger = get_logger(__name__)


def _build_session_store(settings: Settings) -> SessionStore:
    """Return Redis-backed store if redis_url configured, else in-memory."""
    if not settings.redis_url:
        return InMemorySessionStore()
    try:
        import redis.asyncio as aioredis  # type: ignore[import-not-found]

        client = aioredis.from_url(settings.redis_url, decode_responses=False)
        return RedisSessionStore(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "session.redis_unavailable_falling_back_to_memory", error=str(exc)
        )
        return InMemorySessionStore()


def create_app(mode: Literal["internal", "public"] = "internal") -> FastAPI:
    """Construct a FastAPI app with the WI-17 middleware stack and WI-02 routes."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_output=settings.app_env != "development")

    @asynccontextmanager
    async def _lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
        logger.info("portal.startup", mode=mode, env=settings.app_env)
        yield
        logger.info("portal.shutdown", mode=mode)

    app = FastAPI(
        title=f"Compliance Portal ({mode})",
        version="0.1.0",
        docs_url=None if mode == "public" else "/docs",
        redoc_url=None if mode == "public" else "/redoc",
        openapi_url=None if mode == "public" else "/openapi.json",
        lifespan=_lifespan,
        # FastAPI's auto-slash redirects built an absolute URL from the upstream
        # request which dropped the public scheme/port when behind nginx. Use
        # path-only relative redirects (handled by Starlette's redirect_response
        # path resolution) so the browser keeps the original scheme + host:port.
        redirect_slashes=False,
    )

    # ── App state used by middleware/dependencies ────────────────────────────
    app.state.mode = mode
    app.state.settings = settings
    app.state.session_cookie_name = settings.session_cookie_name
    app.state.oidc_flow_cookie_name = "cp_oidc_flow"
    app.state.session_store = _build_session_store(settings)
    app.state.oauth = build_oauth_client(settings)
    app.state.csrf_manager = CsrfTokenManager(
        secret=settings.session_secret.get_secret_value(),
        max_age_s=settings.session_max_age_s,
    )

    # ── PDF service (WI-19) ──────────────────────────────────────────────────
    # Construct one process-scoped PdfService + cache. Components register
    # their export specs against app.state.pdf_registry during their own
    # router setup (Phase 1+ batches).
    app.state.pdf_cache = PdfCache()
    app.state.pdf_registry = get_default_registry()
    app.state.pdf_service = PdfService(
        cache=app.state.pdf_cache,
        # audit_sink is injected at request time via app.state.compliance_client
        # in middleware; this constructor-level sink is None to avoid a
        # blocking dependency on the compliance service at startup.
        audit_sink=None,
    )

    # ── Static files ─────────────────────────────────────────────────────────
    # Mount the JS/CSS assets co-located with the portal package. Skipped when
    # the directory is missing (older test apps that wire only one router via
    # the test harness).
    _static_dir = Path(__file__).resolve().parent / "static"
    if _static_dir.is_dir():
        app.mount(
            "/static", StaticFiles(directory=str(_static_dir)), name="static"
        )

    # ── Root redirect ────────────────────────────────────────────────────────
    # Bare-URL visitors hit "/" and would otherwise see a FastAPI 404. Redirect
    # them to the appropriate landing per mode.
    from fastapi.responses import RedirectResponse

    @app.get("/", include_in_schema=False)
    async def _root_redirect(request: Request):  # type: ignore[no-untyped-def]
        if mode == "internal":
            # If already authenticated (session cookie present), drop them at
            # the dashboards page rather than bouncing back through login.
            sid = request.cookies.get(settings.session_cookie_name)
            if sid:
                store: SessionStore = request.app.state.session_store
                payload = await store.get(sid)
                if payload and payload.get("user"):
                    return RedirectResponse(url="/home", status_code=303)
            # Unauthenticated. In development we don't have an OIDC IdP, so
            # OIDC login would 500 — route bare-URL visitors to dev-login.
            target = (
                "/auth/dev-login?role=admin"
                if settings.app_env == "development"
                else "/auth/login"
            )
            return RedirectResponse(url=target, status_code=307)
        # Public DSR portal: send to the intake form
        return RedirectResponse(url="/dsr/intake", status_code=307)

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(build_auth_router(settings))
    app.include_router(export_router_module.router)
    # Phase 1 Defensible Baseline (mode=internal only — public DSR portal does
    # NOT expose audit / evidence / gates / auditor admin)
    if mode == "internal":
        app.include_router(home_router_module.router)
        app.include_router(audit_router_module.router)
        app.include_router(evidence_router_module.router)
        app.include_router(gates_router_module.router)
        app.include_router(auditor_admin_router_module.router)
        # Phase 2 Regulatory Operations (WI-08, WI-10, WI-11, WI-12)
        app.include_router(dsr_router_module.router)
        app.include_router(incidents_router_module.router)
        app.include_router(incidents_router_module.webhook_router)
        app.include_router(model_cards_router_module.router)
        app.include_router(reports_router_module.router)
        # Phase 3 Scaling Beyond Operator (WI-13, WI-14, WI-15, WI-16)
        app.include_router(dashboards_router_module.router)
        app.include_router(process_knowledge_router_module.router)
        app.include_router(outcomes_router_module.router)
        app.include_router(project_docs_router_module.router)
        # Defensive idempotent registration (modules also register on import)
        audit_router_module.register_audit_pdf_components()
        evidence_router_module.register_evidence_pdf_components()
        gates_router_module.register_gate_pdf_components()
        dsr_router_module.register_dsr_pdf_components()
        incidents_router_module.register_incident_pdf_components()
        model_cards_router_module.register_model_card_pdf_components()
        reports_router_module.register_report_pdf_components()
        dashboards_router_module.register_dashboards_pdf_components()
        process_knowledge_router_module.register_process_knowledge_pdf_components()
        outcomes_router_module.register_outcomes_pdf_components()
        project_docs_router_module.register_project_docs_pdf_components()

    # ── Rate limiter (registers itself as middleware via SlowAPIMiddleware) ──
    # In development the limiter trips on link-checker / Playwright sweeps and
    # masks real bugs as 503s. Raise the ceiling to effectively-unlimited.
    if settings.app_env == "development":
        _internal_rl = 1_000_000
        _public_rl = 1_000_000
    else:
        _internal_rl = 600
        _public_rl = settings.public_rate_limit_per_min
    register_rate_limit(
        app,
        mode=mode,
        public_per_minute=_public_rl,
        internal_per_minute=_internal_rl,
    )

    # ── Middleware (registered REVERSE — last add runs first on inbound) ─────
    # 8. Behavior hook
    app.add_middleware(
        BehaviorHookMiddleware,
        enabled=settings.behavior_hook_enabled,
        webhook_url=str(settings.behavior_hook_url) if settings.behavior_hook_url else None,
    )
    # 7. Audit logging
    app.add_middleware(AuditLoggingMiddleware)
    # 6. CSRF
    csrf_exempt = ("/auth/callback", "/healthz", "/readyz", "/metrics")
    app.add_middleware(
        CsrfMiddleware,
        token_manager=app.state.csrf_manager,
        exempt_paths=csrf_exempt,
        secure_cookie=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )
    # 5. SlowAPI (already configured by register_rate_limit; just attach the middleware)
    app.add_middleware(SlowAPIMiddleware)
    # 4. CORS
    cors_class, cors_kwargs = build_cors_middleware(allowed_origins=settings.cors_origins)
    app.add_middleware(cors_class, **cors_kwargs)
    # 3. Security headers
    app.add_middleware(SecurityHeadersMiddleware, mode=mode)
    # 2. Request ID
    app.add_middleware(RequestIDMiddleware)
    # 1. Forwarded headers (outermost — runs first on inbound)
    app.add_middleware(ForwardedHeaderMiddleware, trusted_cidrs=settings.trusted_proxy_cidrs)

    # ── Exception handlers ───────────────────────────────────────────────────
    register_exception_handlers(app)

    return app


# ── Default uvicorn target ───────────────────────────────────────────────────
app: FastAPI = create_app(mode="internal")


# ── Public DSR portal entrypoint (WI-09) — re-exported for convenience ──────
def create_public_app() -> FastAPI:
    """Build the WI-09 public DSR portal app.

    Imported lazily because the public app depends on a different template
    directory and middleware stack — it shouldn't be a startup-time cost for
    callers that only need the internal app.
    """
    from dsr_portal import create_public_app as _build

    return _build()


__all__ = ["create_app", "app", "get_compliance_client", "create_public_app"]
