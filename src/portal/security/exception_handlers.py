"""Centralized exception handlers — never leak stack traces in HTTP responses."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import ValidationError as PydanticValidationError

from shared.api_client import ScopeViolationError

from ..auth.mfa import StepUpRequired
from ..logging import get_logger
from ..middleware.audit_guard import AuditWriteForbidden

logger = get_logger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    """Wire all centralized handlers into the app."""

    @app.exception_handler(StepUpRequired)
    async def _stepup(request: Request, exc: StepUpRequired) -> JSONResponse | RedirectResponse:
        # HTMX requests get an HX-Redirect header (caught by HTMX client-side)
        if request.headers.get("HX-Request") == "true":
            response = JSONResponse(
                {"detail": "mfa step-up required", "code": "stepup_required"}, status_code=401
            )
            response.headers["HX-Redirect"] = "/auth/login?stepup=1"
            return response
        return RedirectResponse(url="/auth/login?stepup=1", status_code=302)

    @app.exception_handler(ScopeViolationError)
    async def _scope_violation(request: Request, exc: ScopeViolationError) -> JSONResponse:
        logger.warning(
            "scope.violation",
            request_id=getattr(request.state, "request_id", None),
            path=request.url.path,
            code=exc.code,
        )
        return JSONResponse(
            {"detail": "scope violation", "code": "scope_violation"}, status_code=403
        )

    @app.exception_handler(AuditWriteForbidden)
    async def _audit_forbidden(request: Request, exc: AuditWriteForbidden) -> JSONResponse:
        logger.error(
            "audit.write_blocked",
            request_id=getattr(request.state, "request_id", None),
            path=request.url.path,
            # `query` is logged at internal level only; redacted by structlog
            query_redacted=str(exc),
        )
        return JSONResponse(
            {"detail": "internal server error", "code": "audit_write_forbidden"},
            status_code=500,
        )

    @app.exception_handler(PydanticValidationError)
    async def _pydantic(request: Request, exc: PydanticValidationError) -> JSONResponse:
        return JSONResponse(
            {"detail": "validation error", "code": "validation", "errors": exc.errors()},
            status_code=422,
        )

    @app.exception_handler(HTTPException)
    async def _http_exc(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {"detail": exc.detail, "code": f"http_{exc.status_code}"},
            status_code=exc.status_code,
            headers=exc.headers or {},
        )

    @app.exception_handler(Exception)
    async def _generic(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "portal.unhandled_error",
            request_id=getattr(request.state, "request_id", None),
            path=request.url.path,
            error=str(exc),
            type=type(exc).__name__,
        )
        return JSONResponse(
            {"detail": "internal server error", "code": "internal_error"},
            status_code=500,
        )


__all__ = ["register_exception_handlers"]
