"""CSRF middleware — double-submit token validation on state-changing requests.

Used in conjunction with `auth/csrf.py::CsrfTokenManager`. The token is signed
with `itsdangerous` and stored in:
    - cookie:   `csrf` (HttpOnly=False so HTMX can read it for hx-headers)
    - header:   `X-CSRF-Token` for HTMX requests
    - form:     `csrf_token` form field for plain POST forms

Body-preservation contract (F-04)
---------------------------------

For ``application/x-www-form-urlencoded`` POSTs without an ``X-CSRF-Token``
header, this middleware reads the request body to extract ``csrf_token``,
THEN re-buffers the original bytes back into the ASGI receive callable so
downstream route handlers see the form fields intact. Earlier revisions of
this module replaced the receive callable with empty bytes, silently
destroying form data.

The middleware is implemented as a pure ASGI middleware (rather than
``BaseHTTPMiddleware``) because the latter creates a separate Request object
for downstream handlers; overriding ``request._receive`` on the upper
Request does not propagate. Wrapping the ASGI receive callable directly is
the only correct way to inject a buffered body.

Path-exemption contract (F-09)
------------------------------

``_is_exempt`` performs path-segment-aware prefix matching after URL
normalisation. ``/healthz`` matches itself and ``/healthz/...`` but does NOT
match ``/healthzXXX``. Path-traversal sequences (``..``) are stripped before
matching to prevent bypasses such as ``/auth/callback/../api/secret``.
"""

from __future__ import annotations

import posixpath
from typing import Any, Awaitable, Callable, Iterable
from urllib.parse import parse_qsl, urlsplit

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..auth.csrf import CsrfTokenManager

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Cap the body we will buffer for CSRF token extraction. Anything larger than
# this is rejected outright — a CSRF token is < 200 bytes; a form payload of
# many MB is either misuse or an attempt to OOM the middleware.
_FORM_BODY_BUFFER_CAP_BYTES = 1 * 1024 * 1024  # 1 MiB


def _normalise_path(raw_path: str) -> str:
    """Return ``raw_path`` with traversal segments removed.

    Uses :func:`urllib.parse.urlsplit` to discard any query/fragment leakage
    and :func:`posixpath.normpath` to collapse ``..`` segments. The result
    always begins with ``/``.
    """
    parsed = urlsplit(raw_path)
    path = parsed.path or "/"
    # posixpath.normpath collapses "/a/b/../c" -> "/a/c" and "/a/./b" -> "/a/b".
    normalised = posixpath.normpath(path)
    if not normalised.startswith("/"):
        normalised = "/" + normalised
    return normalised


def _parse_cookie_header(raw: bytes) -> dict[str, str]:
    """Minimal cookie parser. Returns name → value (last wins)."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for piece in raw.decode("latin-1", errors="replace").split(";"):
        if "=" not in piece:
            continue
        name, _, value = piece.partition("=")
        out[name.strip()] = value.strip()
    return out


def _extract_charset(content_type: str) -> str:
    """Pull the ``charset=`` parameter out of a Content-Type header.

    Defaults to ``utf-8``.
    """
    for piece in content_type.split(";"):
        piece = piece.strip()
        if piece.lower().startswith("charset="):
            return piece.split("=", 1)[1].strip().strip('"').strip("'") or "utf-8"
    return "utf-8"


async def _read_full_body(receive: Receive) -> bytes | None:
    """Drain ``http.request`` chunks until ``more_body`` is False.

    Returns the assembled bytes, or ``None`` if the buffered size exceeds
    ``_FORM_BODY_BUFFER_CAP_BYTES``. Disconnect events are surfaced as an
    empty body so the middleware can fall through to standard handling.
    """
    buffer = bytearray()
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return bytes(buffer)
        if message["type"] != "http.request":
            continue
        chunk: bytes = message.get("body", b"") or b""
        if len(buffer) + len(chunk) > _FORM_BODY_BUFFER_CAP_BYTES:
            return None
        buffer.extend(chunk)
        if not message.get("more_body", False):
            return bytes(buffer)


def _replayable_receive(buffered_body: bytes) -> Receive:
    """Build a Receive callable that yields the buffered body once, then
    behaves like a closed connection on subsequent calls.
    """
    state = {"sent": False}

    async def _receive() -> Message:
        if not state["sent"]:
            state["sent"] = True
            return {
                "type": "http.request",
                "body": buffered_body,
                "more_body": False,
            }
        # After the body has been delivered, behave like a graceful
        # disconnect so any extra reads do not block forever.
        return {"type": "http.disconnect"}

    return _receive


async def _send_json_response(
    send: Send,
    *,
    status_code: int,
    body: bytes,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": headers,
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class CsrfMiddleware:
    """Pure-ASGI CSRF middleware (see module docstring for design rationale)."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        token_manager: CsrfTokenManager,
        cookie_name: str = "csrf",
        exempt_paths: Iterable[str] = (),
        secure_cookie: bool = True,
        samesite: str = "lax",
    ) -> None:
        self._app = app
        self._tm = token_manager
        self._cookie_name = cookie_name
        self._exempt = tuple(exempt_paths)
        self._secure = secure_cookie
        self._samesite = samesite

    def _is_exempt(self, path: str) -> bool:
        """Path-segment-aware exemption (F-09).

        A configured exempt prefix only matches if either:
          * ``path`` equals the prefix exactly, OR
          * ``path`` begins with ``prefix + "/"``

        This prevents ``/healthz`` from also exempting ``/healthzXXX``.
        Traversal segments are normalised away before comparison.
        """
        normalised = _normalise_path(path)
        for raw in self._exempt:
            prefix = raw.rstrip("/")
            if not prefix:
                # An empty/'/' exempt entry would exempt everything; ignore it.
                continue
            if normalised == prefix or normalised.startswith(prefix + "/"):
                return True
        return False

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")
        raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", []) or []
        header_dict: dict[bytes, bytes] = {k.lower(): v for k, v in raw_headers}
        cookie_header = header_dict.get(b"cookie", b"")
        cookies = _parse_cookie_header(cookie_header)
        cookie_token = cookies.get(self._cookie_name, "")
        header_token = (
            header_dict.get(b"x-csrf-token", b"").decode("latin-1", errors="replace")
        )
        content_type = header_dict.get(b"content-type", b"").decode(
            "latin-1", errors="replace"
        )

        outgoing_receive: Receive = receive

        if method in UNSAFE_METHODS and not self._is_exempt(path):
            if (
                not header_token
                and content_type.startswith("application/x-www-form-urlencoded")
            ):
                # F-04 — read entire body, extract csrf_token, then re-buffer.
                body = await _read_full_body(receive)
                if body is None:
                    await _send_json_response(
                        send,
                        status_code=413,
                        body=(
                            b'{"detail":"request body too large for CSRF inspection",'
                            b'"code":"csrf_body_too_large"}'
                        ),
                    )
                    return
                charset = _extract_charset(content_type)
                try:
                    decoded = body.decode(charset, errors="replace")
                except LookupError:
                    decoded = body.decode("utf-8", errors="replace")
                for key, value in parse_qsl(
                    decoded, keep_blank_values=True, strict_parsing=False
                ):
                    if key == "csrf_token":
                        header_token = value
                        break
                outgoing_receive = _replayable_receive(body)

            if not self._tm.matches(cookie_token, header_token):
                await _send_json_response(
                    send,
                    status_code=403,
                    body=(
                        b'{"detail":"CSRF token missing or invalid",'
                        b'"code":"csrf_invalid"}'
                    ),
                )
                return

        # On GET responses without a CSRF cookie, set one as the response
        # leaves. We wrap ``send`` so we can append a Set-Cookie header.
        needs_token_cookie = (
            method == "GET" and self._cookie_name not in cookies
        )

        if needs_token_cookie:
            new_token = self._tm.generate()
            cookie_value = self._build_set_cookie(new_token)
            wrapped_send = self._wrap_send_with_cookie(send, cookie_value)
            await self._app(scope, outgoing_receive, wrapped_send)
        else:
            await self._app(scope, outgoing_receive, send)

    def _build_set_cookie(self, token: str) -> bytes:
        """Construct a ``Set-Cookie`` header value for the CSRF cookie."""
        parts = [
            f"{self._cookie_name}={token}",
            "Path=/",
            f"SameSite={self._samesite.capitalize()}",
        ]
        if self._secure:
            parts.append("Secure")
        # HttpOnly is intentionally OMITTED so HTMX can read the cookie.
        return "; ".join(parts).encode("latin-1")

    @staticmethod
    def _wrap_send_with_cookie(send: Send, cookie_value: bytes) -> Send:
        """Return a Send wrapper that injects a Set-Cookie header on the
        first ``http.response.start`` message."""
        added: dict[str, bool] = {"done": False}

        async def _send(message: Message) -> None:
            if not added["done"] and message["type"] == "http.response.start":
                headers = MutableHeaders(raw=message.setdefault("headers", []))
                headers.append("set-cookie", cookie_value.decode("latin-1"))
                added["done"] = True
            await send(message)

        return _send


__all__ = ["CsrfMiddleware", "UNSAFE_METHODS"]
