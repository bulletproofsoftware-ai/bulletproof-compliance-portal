"""Helpers for building internal redirect targets out of request data.

Several routers redirect to a route whose path embeds an id taken straight
from the request (``/admin/auditor-engagements/{engagement_id}``). The prefix
is a literal, so the target cannot leave the origin, but an unencoded id can
still add a query string, a fragment, or a traversal step to the URL the
browser is told to follow. :func:`safe_url_segment` removes that.
"""

from __future__ import annotations

from urllib.parse import quote

__all__ = ["safe_url_segment"]


def safe_url_segment(value: str) -> str:
    """Percent-encode ``value`` for use as one path segment of an internal URL.

    ``quote`` with ``safe=""`` encodes every reserved character, so "/", "?"
    and "#" cannot introduce a new segment, query or fragment. Dots are
    unreserved and survive encoding, so dots-only names are rejected outright
    rather than left to browser path normalisation.

    Raises
    ------
    ValueError
        If ``value`` is not a non-empty string, or is a dots-only name.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("url segment must be a non-empty string")
    if set(value) == {"."}:
        raise ValueError(f"url segment must not be a traversal step: {value!r}")
    return quote(value, safe="")
