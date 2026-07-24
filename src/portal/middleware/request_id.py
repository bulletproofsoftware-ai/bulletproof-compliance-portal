"""Per-request correlation ID middleware.

Reads `X-Request-ID` from the inbound request if present (and a trusted-proxy
header was already normalized — see ForwardedHeaderMiddleware), otherwise
generates a fresh UUID. Echoes the id back in the response.
"""

from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..logging import bind_request_context, clear_request_context

HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        rid = request.headers.get(HEADER) or uuid.uuid4().hex
        request.state.request_id = rid
        bind_request_context(request_id=rid)
        try:
            response: Response = await call_next(request)
        finally:
            clear_request_context()
        response.headers[HEADER] = rid
        return response


__all__ = ["RequestIDMiddleware", "HEADER"]
