"""Trusted-proxy header normalizer (X-Forwarded-For / Proto / Host).

Honors X-Forwarded-* headers ONLY when the immediate peer's IP is in the
configured trusted CIDR list. Otherwise, drops them and uses the direct TCP
connection metadata.
"""

from __future__ import annotations

import ipaddress

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class ForwardedHeaderMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, trusted_cidrs: list[str]) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._networks = [ipaddress.ip_network(c, strict=False) for c in trusted_cidrs]

    def _is_trusted(self, peer_ip: str) -> bool:
        try:
            ip = ipaddress.ip_address(peer_ip)
        except ValueError:
            return False
        return any(ip in net for net in self._networks)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        peer = request.client.host if request.client else ""
        if peer and self._is_trusted(peer):
            xff = request.headers.get("x-forwarded-for")
            if xff:
                # left-most is the original client
                first = xff.split(",")[0].strip()
                if first:
                    request.scope["client"] = (first, request.client.port if request.client else 0)
            xfp = request.headers.get("x-forwarded-proto")
            if xfp:
                request.scope["scheme"] = xfp.strip().lower()
        return await call_next(request)


__all__ = ["ForwardedHeaderMiddleware"]
