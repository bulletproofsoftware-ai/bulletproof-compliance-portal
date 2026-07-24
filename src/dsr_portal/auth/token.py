"""Public-portal capability ACL (AMD-05).

The public DSR portal does NOT use OIDC sessions. Submitter identity is
established by the (reference, email) pair returned at submission time, plus
a signed token that embeds an explicit capability claim.

AMD-05 mandates a 4-item ACL:

    SUBMIT            — POST /dsr/submit
    STATUS_CHECK      — POST /dsr/status (lookup by reference+email)
    IDENTITY_UPLOAD   — POST /dsr/identity-upload (re-upload after insufficient)
    RECEIPT_DOWNLOAD  — GET /dsr/receipt (PDF receipt)

Any operation outside the ACL → 403. The compliance service enforces an
identical ACL on the service-account token; this module enforces the same
constraints client-side as defense in depth.

Tokens are HMAC-signed with itsdangerous; max age 7 days (same as DSR delivery
tokens). Capability claim is the operation enum value.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


class TokenCapability(StrEnum):
    SUBMIT = "submit"
    STATUS_CHECK = "status_check"
    IDENTITY_UPLOAD = "identity_upload"
    RECEIPT_DOWNLOAD = "receipt_download"


_SERIALIZER_SALT = "dsr-portal-public-token-v1"
_DEFAULT_MAX_AGE_S = 7 * 24 * 3600  # 7 days


@dataclass(frozen=True)
class PublicToken:
    reference: str
    email: str
    capability: TokenCapability


class PublicTokenManager:
    """Issues and verifies signed public-portal tokens with capability ACL.

    The signing secret MUST be DIFFERENT from the internal portal's session
    secret — public token compromise must not yield internal access.
    """

    def __init__(self, *, secret: str, max_age_s: int = _DEFAULT_MAX_AGE_S) -> None:
        if not secret or len(secret) < 32:
            raise ValueError("public-token secret must be at least 32 characters")
        self._serializer = URLSafeTimedSerializer(secret, salt=_SERIALIZER_SALT)
        self._max_age_s = max_age_s

    def issue(
        self, *, reference: str, email: str, capability: TokenCapability
    ) -> str:
        if not reference or not email:
            raise ValueError("reference and email are required")
        payload = {
            "ref": reference,
            "email": email.lower().strip(),
            "cap": capability.value,
        }
        return self._serializer.dumps(payload)

    def verify(self, token: str) -> PublicToken:
        """Parse + verify; raises HTTPException(401/410) on failure."""
        try:
            payload = self._serializer.loads(token, max_age=self._max_age_s)
        except SignatureExpired as exc:
            raise HTTPException(
                status_code=status.HTTP_410_GONE, detail="token_expired"
            ) from exc
        except BadSignature as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="bad_token"
            ) from exc
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="bad_token_shape"
            )
        try:
            cap = TokenCapability(payload["cap"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="bad_capability"
            ) from exc
        return PublicToken(
            reference=str(payload.get("ref", "")),
            email=str(payload.get("email", "")),
            capability=cap,
        )


def require_capability(
    required: TokenCapability,
):
    """FastAPI dependency factory — extracts token from query/form/header and
    enforces capability. 403 with `service_account_acl_violation` if mismatch."""

    async def _dep(request: Request) -> PublicToken:
        # Token can come from header (X-DSR-Token), query (?token=), or form.
        token: str | None = None
        token = request.headers.get("X-DSR-Token")
        if not token:
            token = request.query_params.get("token")
        if not token and request.method == "POST":
            try:
                form = await request.form()
                token = form.get("token")  # type: ignore[assignment]
            except Exception:  # noqa: BLE001
                token = None
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="token_required"
            )

        mgr: PublicTokenManager = getattr(request.app.state, "public_token_mgr")
        public_token = mgr.verify(token)

        if public_token.capability != required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="service_account_acl_violation",
            )
        return public_token

    _dep.__name__ = f"require_capability_{required.value}"
    return _dep


__all__ = [
    "TokenCapability",
    "PublicToken",
    "PublicTokenManager",
    "require_capability",
]
