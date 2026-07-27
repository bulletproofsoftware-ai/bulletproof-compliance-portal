"""Rate limiting via slowapi.

Limiting is applied GLOBALLY by a single default limit, not per-route. There are
no `@limiter.limit(...)` decorators anywhere in this codebase; every request is
covered by `default_limits` below because `SlowAPIMiddleware` (registered in
`portal/main.py` and `dsr_portal/main.py`) exempts a route only when it is
explicitly exempted or carries its own decorator — neither applies here.

Defaults differ for the internal vs. public portals; see `register_rate_limit`.

Key function is `get_remote_address`, which reads `request.scope["client"]`.
`ForwardedHeaderMiddleware` must run BEFORE this middleware so the key is the
real client IP rather than the proxy's. Starlette runs middleware in reverse
registration order, so ForwardedHeaderMiddleware is added LAST in main.py.
"""

from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


def build_limiter(*, default_per_minute: int = 600) -> Limiter:
    """Create a Limiter using the IP address (post forwarded-header normalize)
    as the key. Defaults are per-minute."""
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[f"{default_per_minute}/minute"],
        headers_enabled=True,
        in_memory_fallback_enabled=True,
    )
    return limiter


def register_rate_limit(
    app: FastAPI,
    *,
    mode: Literal["internal", "public"] = "internal",
    public_per_minute: int = 100,
    internal_per_minute: int = 600,
) -> Limiter:
    """Attach a Limiter to the app and register the 429 handler."""
    default = public_per_minute if mode == "public" else internal_per_minute
    limiter = build_limiter(default_per_minute=default)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    return limiter


def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Clean 429 with Retry-After. The default slowapi handler is a stock
    Starlette response; this wrapper standardizes the body.

    MUST be synchronous. slowapi's SlowAPIMiddleware runs the exception handler
    from synchronous code and silently substitutes its own stock handler for any
    coroutine (slowapi/middleware.py: "cannot execute asynchronous code in a
    synchronous middleware, -> fallback on default exception handler"). Declaring
    this `async def` made the body below dead code on the middleware path —
    clients received slowapi's stock {"error": ...} instead. Do not re-add async.
    """
    retry_after = getattr(exc, "retry_after", 60)
    return JSONResponse(
        status_code=429,
        content={
            "detail": "rate limit exceeded",
            "code": "rate_limit_exceeded",
            "retry_after_s": retry_after,
        },
        headers={"Retry-After": str(retry_after)},
    )


__all__ = ["build_limiter", "register_rate_limit"]
