"""WeasyPrint configuration — fonts, fetchers, optimization flags.

This module centralizes the construction of `weasyprint.HTML` and
`weasyprint.CSS` objects. The renderer (service.py) MUST go through these
helpers — direct construction of `weasyprint.HTML(...)` outside this file is
a violation of AMD-02 (it would bypass the safe URL fetcher).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import weasyprint
from weasyprint.text.fonts import FontConfiguration

from .url_fetcher import STATIC_ROOT, safe_url_fetcher


def get_font_config() -> FontConfiguration:
    """Singleton font config. Re-created per worker process is fine; WeasyPrint
    caches @font-face resolutions internally."""
    return FontConfiguration()


def base_url_for_static() -> str:
    """`base_url` passed to weasyprint.HTML — anchors all relative refs into
    STATIC_ROOT. Combined with safe_url_fetcher, no fetch can escape this dir."""
    return f"file://{STATIC_ROOT}/"


def make_html(html_string: str) -> weasyprint.HTML:
    """Construct a weasyprint.HTML with the locked-down url_fetcher.

    NEVER construct weasyprint.HTML(...) directly elsewhere — use this helper.
    """
    return weasyprint.HTML(
        string=html_string,
        base_url=base_url_for_static(),
        url_fetcher=safe_url_fetcher,
        encoding="utf-8",
    )


def make_print_css() -> weasyprint.CSS:
    """Load the shared print stylesheet through the locked-down fetcher.

    The print.css file lives under STATIC_ROOT, so the fetcher accepts it.
    """
    css_path = Path(STATIC_ROOT) / "print.css"
    if not css_path.is_file():
        raise FileNotFoundError(f"print.css not found at {css_path}")
    return weasyprint.CSS(
        filename=str(css_path),
        url_fetcher=safe_url_fetcher,
        font_config=get_font_config(),
    )


def write_pdf(html: weasyprint.HTML, *, stylesheets: list[weasyprint.CSS] | None = None) -> bytes:
    """Render to bytes with the consistent optimization profile.

    `optimize_images=True` re-encodes inline images; font subsetting is the
    WeasyPrint default (full_fonts=False) and shrinks output ~30%.
    """
    kwargs: dict[str, Any] = {
        "stylesheets": stylesheets or [],
        "font_config": get_font_config(),
        "optimize_images": True,
    }
    return html.write_pdf(**kwargs)


__all__ = ["get_font_config", "base_url_for_static", "make_html", "make_print_css", "write_pdf"]
