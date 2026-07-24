"""Security headers middleware — CSP, HSTS, X-Frame-Options, etc.

Per WI-17. Different defaults for the internal portal vs. the public DSR
portal. CSP intentionally allows `'unsafe-inline'` for STYLES (HTMX template
requirement) but NEVER for scripts.
"""

from __future__ import annotations

import os
from typing import Literal

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


def _build_csp() -> str:
    # Development: allow inline scripts + unsafe-eval because several templates
    # ship <script> blocks AND HTMX hx-on::after-request="..." uses Function()
    # to evaluate the inline handler (CSP-restricted in strict mode). Production
    # build refactors these to external bundles + nonces and uses hx-ext for
    # custom side-effects.
    #
    # img-src — in development, allow https:* so that shields.io / GitHub /
    # codecov status badges embedded inside rendered project markdown docs can
    # load. Production keeps the strict 'self' data: policy.
    is_dev = os.environ.get("APP_ENV", "production") == "development"
    script_src = "script-src 'self'"
    img_src = "img-src 'self' data:"
    if is_dev:
        script_src = "script-src 'self' 'unsafe-inline' 'unsafe-eval'"
        img_src = "img-src 'self' data: https:"
    return (
        "default-src 'self'; "
        f"{script_src}; "
        "style-src 'self' 'unsafe-inline'; "
        f"{img_src}; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "object-src 'none'"
    )


_BASE_CSP = _build_csp()

HEADERS_INTERNAL: dict[str, str] = {
    "Content-Security-Policy": _BASE_CSP,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}

HEADERS_PUBLIC: dict[str, str] = {
    **HEADERS_INTERNAL,
    "Referrer-Policy": "same-origin",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, mode: Literal["internal", "public"] = "internal") -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._headers = HEADERS_PUBLIC if mode == "public" else HEADERS_INTERNAL

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        for k, v in self._headers.items():
            # Don't overwrite if a route already set it intentionally.
            response.headers.setdefault(k, v)
        return response


__all__ = ["SecurityHeadersMiddleware", "HEADERS_INTERNAL", "HEADERS_PUBLIC"]
