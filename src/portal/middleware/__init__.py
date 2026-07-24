"""WI-17 Security middleware package.

Order of registration is non-negotiable (request-flow):

    1. ForwardedHeaderMiddleware
    2. RequestIDMiddleware
    3. SecurityHeadersMiddleware
    4. RateLimitMiddleware  (slowapi-based — installed via `register_rate_limit`)
    5. CsrfMiddleware
    6. AuditLoggingMiddleware
    7. BehaviorHookMiddleware

All middlewares are pure ASGI / Starlette BaseHTTPMiddleware. None block on
external IO that would couple availability to non-essential paths.
"""

from .audit import AuditLoggingMiddleware
from .audit_guard import AuditWriteForbidden, install_audit_guard
from .cors import build_cors_middleware
from .csrf_mw import CsrfMiddleware
from .forwarded import ForwardedHeaderMiddleware
from .rate_limit import build_limiter, register_rate_limit
from .request_id import RequestIDMiddleware
from .security_headers import SecurityHeadersMiddleware

__all__ = [
    "AuditLoggingMiddleware",
    "AuditWriteForbidden",
    "install_audit_guard",
    "build_cors_middleware",
    "CsrfMiddleware",
    "ForwardedHeaderMiddleware",
    "build_limiter",
    "register_rate_limit",
    "RequestIDMiddleware",
    "SecurityHeadersMiddleware",
]
