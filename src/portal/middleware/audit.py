"""Audit logging middleware — every request emits one structured audit log.

PER WI-17:
    - Health (`/healthz`, `/readyz`) and static assets are excluded.
    - PII is redacted by the structlog processor (AMD-17).
    - Failures to emit do NOT block the response (logged at ERROR).

Real-time forwarding to the compliance service (`record_audit_event`) is wired
from app.state.compliance_client when present; otherwise we only emit a local
structured log line. This makes tests trivial (no compliance service required
to verify the middleware contract).
"""

from __future__ import annotations

import time
from typing import Iterable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..logging import get_logger

logger = get_logger(__name__)

DEFAULT_EXCLUDED = ("/healthz", "/readyz", "/metrics", "/static", "/favicon.ico")


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,  # type: ignore[no-untyped-def]
        *,
        excluded: Iterable[str] = DEFAULT_EXCLUDED,
        forward_to_compliance: bool = True,
    ) -> None:
        super().__init__(app)
        self._excluded = tuple(excluded)
        self._forward = forward_to_compliance

    def _is_excluded(self, path: str) -> bool:
        return any(path == e or path.startswith(e + "/") or path == e for e in self._excluded)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if self._is_excluded(request.url.path):
            return await call_next(request)

        started = time.perf_counter()
        response: Response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)

        # Resolve user from app.state if a session middleware attached one.
        user = getattr(request.state, "user", None)
        user_id = getattr(user, "sub", None) if user else None

        payload = {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "request_id": getattr(request.state, "request_id", None),
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "duration_ms": duration_ms,
        }
        logger.info("portal.http.request", user_id=user_id, **payload)

        # Best-effort forwarding to compliance service
        compliance_client = getattr(request.app.state, "compliance_client", None)
        if self._forward and compliance_client is not None:
            try:
                await compliance_client.record_audit_event(
                    audit_type="portal.http.request",
                    user_id=user_id,
                    classification="internal",
                    payload=payload,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("audit.emit_failed", error=str(exc), path=request.url.path)

        return response


__all__ = ["AuditLoggingMiddleware", "DEFAULT_EXCLUDED"]
