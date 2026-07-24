"""Signed CSRF token primitives — used by middleware/csrf_mw.py."""

from __future__ import annotations

import secrets

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class CsrfTokenManager:
    """Generates and verifies signed CSRF tokens.

    Pattern: double-submit. The cookie carries a signed token; state-changing
    requests must echo the same value in the X-CSRF-Token header (HTMX) or in
    a `csrf_token` form field. Both must verify against the same secret AND
    match each other.
    """

    SALT = "compliance-portal:csrf"

    def __init__(self, secret: str, *, max_age_s: int = 3600) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key=secret, salt=self.SALT)
        self.max_age_s = max_age_s

    def generate(self) -> str:
        """Issue a fresh signed token."""
        raw = secrets.token_urlsafe(24)
        return self._serializer.dumps(raw)

    def verify(self, token: str) -> bool:
        """True if the token is well-formed, signed, and within max_age."""
        if not token:
            return False
        try:
            self._serializer.loads(token, max_age=self.max_age_s)
            return True
        except (BadSignature, SignatureExpired):
            return False

    def matches(self, cookie_token: str, header_token: str) -> bool:
        """Both tokens valid AND equal."""
        if not self.verify(cookie_token) or not self.verify(header_token):
            return False
        return secrets.compare_digest(cookie_token, header_token)


__all__ = ["CsrfTokenManager"]
