"""Jinja2 environment factory for the portal.

Templates live alongside this package (`src/portal/templates/*`). Routers obtain
the env via `get_templates()`. The env is configured with autoescape ON for
HTML/XML and a small set of helpers (csrf token, classification badge).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape

_TEMPLATE_DIR = Path(__file__).resolve().parent


def _classification_badge(value: str | None) -> str:
    """Return a CSS class name for a data-classification badge.

    Public templates use these to color-code without hardcoding palette logic.
    """
    if not value:
        return "badge badge-unknown"
    v = value.lower()
    if v == "public":
        return "badge badge-public"
    if v == "internal":
        return "badge badge-internal"
    if v == "confidential":
        return "badge badge-confidential"
    if v == "restricted":
        return "badge badge-restricted"
    return "badge badge-unknown"


def _sla_band(remaining_seconds: float | None) -> str:
    """REQ-CPL-009 SLA color band — red <1h, amber <4h, else green."""
    if remaining_seconds is None:
        return "green"
    if remaining_seconds <= 0:
        return "red"
    if remaining_seconds <= 3600:
        return "red"
    if remaining_seconds <= 4 * 3600:
        return "amber"
    return "green"


@lru_cache(maxsize=1)
def get_templates() -> Jinja2Templates:
    """Process-singleton Jinja2 environment.

    Adds:
      - autoescape for html/xml/htm
      - filter `classification_badge`
      - filter `sla_band`
      - global `now()` (UTC datetime, for footer timestamps)
    """
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
    env = templates.env
    env.autoescape = select_autoescape(default=True, default_for_string=True)
    env.filters["classification_badge"] = _classification_badge
    env.filters["sla_band"] = _sla_band

    from datetime import UTC, datetime

    env.globals["now"] = lambda: datetime.now(UTC)

    from ..nav import nav_for as _nav_for

    env.globals["nav_for"] = _nav_for
    return templates


__all__ = ["get_templates"]
