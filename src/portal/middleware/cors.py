"""Strict CORS — explicit origin allowlist, never wildcards.

Wraps Starlette's CORSMiddleware with our settings. Wildcards are rejected at
build-time per WI-17 (`Access-Control-Allow-Origin: *` would defeat CSRF
double-submit and expose authenticated APIs to any origin).
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.cors import CORSMiddleware


def build_cors_middleware(
    *,
    allowed_origins: list[str],
    allow_credentials: bool = True,
) -> tuple[type[CORSMiddleware], dict[str, Any]]:
    """Return (middleware_class, kwargs) for app.add_middleware().

    Raises ValueError on any wildcard origin — the build fails fast.
    """
    cleaned: list[str] = []
    for o in allowed_origins:
        o = o.strip()
        if not o:
            continue
        if o == "*" or o.startswith("*"):
            raise ValueError(
                f"CORS: wildcard origin {o!r} not allowed. Set explicit origins."
            )
        cleaned.append(o)

    if not cleaned:
        # An empty allowlist effectively disables CORS (only same-origin).
        cleaned = []

    return CORSMiddleware, {
        "allow_origins": cleaned,
        "allow_credentials": allow_credentials,
        "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID", "HX-Request", "HX-Target"],
        "expose_headers": ["X-Request-ID"],
        "max_age": 600,
    }


__all__ = ["build_cors_middleware"]
