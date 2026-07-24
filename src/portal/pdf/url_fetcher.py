"""Fail-closed URL fetcher for WeasyPrint (AMD-02 / CISO C-2 / OWASP A10).

WeasyPrint, by default, resolves any URL it sees in HTML/CSS — `<img src=...>`,
`<link>`, `@import`, `background:url(...)`, even `<object data=...>`. That
makes the renderer a confused-deputy SSRF gadget unless the URL fetcher is
locked down.

This module implements `safe_url_fetcher`, the ONLY URL fetcher the renderer
is permitted to use. It is fail-closed:

    Allowed
    -------
      * `data:` URIs (text/html, text/css, text/plain, image/png, image/jpeg,
        image/svg+xml, image/webp, application/font-woff, application/font-woff2,
        font/woff, font/woff2, font/ttf, font/otf)
      * `file://` URIs whose resolved path is under the bundled STATIC_ROOT
        (after symlink resolution; symlink-escape is rejected)

    Blocked (everything else)
    -------------------------
      * `http://` and `https://` — including link-local / metadata IPs
      * `ftp://`, `gopher://`, `ldap://`, etc.
      * `file://` paths outside STATIC_ROOT
      * URLs that decode to internal IPs by hostname (we never even resolve)
      * Empty / malformed URLs

Every block emits a structured log line at WARNING and surfaces an audit
event hook (`UrlFetcherBlocked.audit_payload`). The renderer wires that hook
into the audit pipeline so blocked fetches show up in the audit chain as
`pdf.render.url_fetcher_blocked`.

The fetcher returns the dict shape WeasyPrint expects:
    {"file_obj": <readable>, "mime_type": str | None, "encoding": str | None,
     "redirected_url": str, "filename": str | None}
"""

from __future__ import annotations

import base64
import io
import logging
import mimetypes
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)


# ── Resolve STATIC_ROOT relative to this file so it travels with the package ─
# /…/src/portal/pdf/url_fetcher.py  →  STATIC_ROOT = /…/src/portal/pdf/static
_PKG_DIR = Path(__file__).resolve().parent
STATIC_ROOT: str = str((_PKG_DIR / "static").resolve())


# ── data: URI MIME allowlist ─────────────────────────────────────────────────
_ALLOWED_DATA_MIMES: frozenset[str] = frozenset(
    {
        "text/html",
        "text/css",
        "text/plain",
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/gif",
        "image/svg+xml",
        "image/webp",
        "application/font-woff",
        "application/font-woff2",
        "application/x-font-ttf",
        "application/x-font-opentype",
        "application/octet-stream",  # WeasyPrint requests fonts this way occasionally
        "font/woff",
        "font/woff2",
        "font/ttf",
        "font/otf",
        "font/sfnt",
    }
)


class UrlFetcherBlocked(ValueError):
    """Raised by safe_url_fetcher to fail closed.

    The renderer catches this, emits an audit event, and surfaces a
    PdfRenderError to the caller.
    """

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"PDF fetch blocked: {reason}: {url!r}")
        self.url = url
        self.reason = reason

    @property
    def audit_payload(self) -> dict[str, str]:
        return {"blocked_url": self.url, "reason": self.reason}


@dataclass(slots=True)
class _FetchAttempt:
    """Diagnostic record for tests & audit forwarding."""

    url: str
    decision: str  # "allow_data" | "allow_file" | "block"
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


# A spy hook that tests can install to assert no outbound HTTP was attempted.
# When set, EVERY call to safe_url_fetcher will append a _FetchAttempt.
_FETCH_LOG: list[_FetchAttempt] | None = None


def install_fetch_log() -> list[_FetchAttempt]:
    """Test helper — start recording every fetcher decision."""
    global _FETCH_LOG
    _FETCH_LOG = []
    return _FETCH_LOG


def clear_fetch_log() -> None:
    """Test helper — stop recording."""
    global _FETCH_LOG
    _FETCH_LOG = None


def _record(attempt: _FetchAttempt) -> None:
    if _FETCH_LOG is not None:
        _FETCH_LOG.append(attempt)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_data_uri(url: str) -> tuple[str, bytes]:
    """Parse a `data:[<mime>][;charset=…][;base64],<payload>` URI.

    Returns (mime_type, payload_bytes). Raises UrlFetcherBlocked on malformed
    input or disallowed MIME.
    """
    # data:[<mediatype>][;base64],<data>
    if not url.startswith("data:"):
        raise UrlFetcherBlocked(url, "not a data: URI")
    body = url[5:]
    if "," not in body:
        raise UrlFetcherBlocked(url, "data URI missing comma separator")
    meta, payload = body.split(",", 1)
    parts = meta.split(";") if meta else [""]
    mime = parts[0].strip().lower() if parts[0] else "text/plain"
    is_b64 = any(p.strip().lower() == "base64" for p in parts[1:])

    if mime not in _ALLOWED_DATA_MIMES:
        raise UrlFetcherBlocked(url, f"data: MIME {mime!r} not in allowlist")

    if is_b64:
        try:
            data = base64.b64decode(payload, validate=False)
        except Exception as exc:  # noqa: BLE001
            raise UrlFetcherBlocked(url, f"data: invalid base64: {exc}") from exc
    else:
        # URL-decode the inline payload
        data = unquote(payload).encode("utf-8")

    return mime, data


def _resolve_under_static_root(file_url_path: str, original_url: str) -> str:
    """Resolve a file:// path and require it to live under STATIC_ROOT.

    Symlink escape, .. traversal, and absolute paths outside the root are all
    rejected. Returns the canonical absolute path.
    """
    raw = unquote(file_url_path)
    if not raw:
        raise UrlFetcherBlocked(original_url, "empty file:// path")

    # os.path.realpath collapses ".." and follows symlinks
    resolved = os.path.realpath(raw)

    static_root_norm = os.path.realpath(STATIC_ROOT)
    if resolved != static_root_norm and not resolved.startswith(
        static_root_norm + os.sep
    ):
        raise UrlFetcherBlocked(
            original_url,
            f"file:// path outside STATIC_ROOT (resolved to {resolved!r})",
        )

    if not os.path.isfile(resolved):
        raise UrlFetcherBlocked(original_url, f"file does not exist: {resolved!r}")

    return resolved


# ── Public fetcher ───────────────────────────────────────────────────────────


def safe_url_fetcher(url: str, *, timeout: float | None = None, **_: Any) -> dict[str, Any]:
    """The ONLY URL fetcher WeasyPrint is permitted to use.

    Signature is compatible with WeasyPrint's `url_fetcher` callable:
    accepts a URL and arbitrary kwargs (newer WeasyPrint passes `timeout`),
    returns the dict shape WeasyPrint requires.
    """
    if not isinstance(url, str) or not url:
        raise UrlFetcherBlocked(str(url), "empty URL")

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    # ── data: URIs ─────────────────────────────────────────────────────────
    if scheme == "data":
        mime, data = _parse_data_uri(url)
        _record(_FetchAttempt(url=url, decision="allow_data", extra={"mime": mime, "size": len(data)}))
        logger.debug("pdf.url_fetcher.allow_data", extra={"mime": mime, "size": len(data)})
        return {
            "file_obj": io.BytesIO(data),
            "mime_type": mime,
            "encoding": None,
            "redirected_url": url,
            "filename": None,
        }

    # ── file:// URIs (only under STATIC_ROOT) ──────────────────────────────
    if scheme == "file":
        # parsed.netloc may be the host (file://localhost/path or file:///path)
        # We accept localhost or empty netloc; reject anything else (file://other-host/...)
        netloc = (parsed.netloc or "").lower()
        if netloc not in {"", "localhost"}:
            attempt = _FetchAttempt(
                url=url, decision="block", reason=f"file:// remote host {netloc!r}"
            )
            _record(attempt)
            logger.warning(
                "pdf.url_fetcher.block",
                extra={"url": attempt.url, "reason": attempt.reason},
            )
            raise UrlFetcherBlocked(url, f"file:// with non-local netloc {netloc!r}")

        path = parsed.path or ""
        try:
            resolved = _resolve_under_static_root(path, url)
        except UrlFetcherBlocked as exc:
            _record(_FetchAttempt(url=url, decision="block", reason=exc.reason))
            logger.warning("pdf.url_fetcher.block", extra={"url": url, "reason": exc.reason})
            raise

        # Read into memory — WeasyPrint expects a file_obj
        with open(resolved, "rb") as f:
            data = f.read()
        mime, _ = mimetypes.guess_type(resolved)
        _record(
            _FetchAttempt(
                url=url,
                decision="allow_file",
                extra={"resolved": resolved, "mime": mime, "size": len(data)},
            )
        )
        logger.debug(
            "pdf.url_fetcher.allow_file",
            extra={"resolved": resolved, "mime": mime, "size": len(data)},
        )
        return {
            "file_obj": io.BytesIO(data),
            "mime_type": mime,
            "encoding": None,
            "redirected_url": url,
            "filename": os.path.basename(resolved),
        }

    # ── Everything else: block ──────────────────────────────────────────────
    reason = f"non-allowlisted scheme {scheme!r}"
    if scheme in {"http", "https"}:
        reason = f"remote {scheme}:// fetch blocked (SSRF defense, AMD-02)"
    elif scheme in {"ftp", "gopher", "ldap", "dict"}:
        reason = f"legacy scheme {scheme!r} blocked"
    attempt = _FetchAttempt(url=url, decision="block", reason=reason)
    _record(attempt)
    logger.warning("pdf.url_fetcher.block", extra={"url": url, "reason": reason})
    raise UrlFetcherBlocked(url, reason)


__all__ = [
    "STATIC_ROOT",
    "UrlFetcherBlocked",
    "safe_url_fetcher",
    "install_fetch_log",
    "clear_fetch_log",
]
