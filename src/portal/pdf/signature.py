"""Signature handling — JWKS-aware delegation to compliance service.

Two signature flows live here:

    1. **Body signature (AMD-04)**
       The compliance service signs the canonical *body* (the data that
       becomes the PDF) with its Ed25519 private key. The portal receives a
       `SignatureSpec` and embeds it via metadata.embed_pdf_metadata under
       /X-Compliance-Signature. Verifiers resolve the `signing_key_id`
       against the compliance service's JWKS endpoint
       (`/api/v1/compliance/.well-known/jwks.json`).

    2. **Byterange signature (AMD-08)**
       For regulatory reports (WI-12 SOX / NY DFS / EU AI Act / NAIC), a body
       signature alone is not enough — a verifier must be able to detect
       byte-level edits to the rendered PDF. We use a two-stage flow:

           (a) Render PDF (with body signature already in /Info)
           (b) Compute SHA-256 over a deterministic byterange of the rendered
               PDF
           (c) Send digest to compliance service
                   POST /api/v1/compliance/pdf/sign-byterange
                   { document_id, byterange_digest_b64, key_id_hint? }
               → { signature_b64, key_id, alg: "Ed25519" }
           (d) Embed the byterange signature under
               /X-Compliance-PDF-Byte-Signature
           (e) Audit event records both body_sha256 and pdf_byte_sha256

The portal NEVER holds Ed25519 private keys. The signing service is the
trust anchor; key custody never crosses the boundary.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SignatureSpec(BaseModel):
    """Body signature returned by the compliance service.

    `signature` is the Ed25519 detached signature, base64-encoded (standard
    or urlsafe — both are accepted by the verifier per JOSE conventions).
    """

    model_config = ConfigDict(frozen=True)

    signature: str = Field(min_length=1, description="Ed25519 signature, base64")
    signed_at: datetime = Field(description="UTC timestamp the service signed at")
    signed_by: str = Field(min_length=1, description="Compliance service identity")
    signing_key_id: str = Field(
        min_length=1, description="JWK kid resolvable via JWKS endpoint"
    )
    body_sha256_hex: str | None = Field(
        default=None,
        description="SHA-256 (hex) of the canonical body that was signed",
    )

    @field_validator("signature", "signed_by", "signing_key_id")
    @classmethod
    def _strip_check(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        return v

    def to_pdf_info_dict(self) -> dict[str, str]:
        d = {
            "/X-Compliance-Signature": self.signature,
            "/X-Compliance-Signed-At": self.signed_at.astimezone(
                UTC
            ).isoformat(timespec="seconds"),
            "/X-Compliance-Signed-By": self.signed_by,
            "/X-Compliance-Key-Id": self.signing_key_id,
        }
        if self.body_sha256_hex:
            d["/X-Compliance-Body-Sha256"] = self.body_sha256_hex
        return d


# ── Byterange signing protocol (AMD-08) ──────────────────────────────────────


class SigningClient(Protocol):
    """Protocol the PdfService uses to talk to the compliance signing endpoint.

    Production implementation lives in `shared.api_client.ComplianceClient`
    (added in WI-12 / WI-19 wiring). Tests inject a stub.
    """

    async def sign_pdf_byterange(
        self,
        *,
        document_id: str,
        byterange_digest_hex: str,
        key_id_hint: str | None = None,
    ) -> tuple[str, str]:
        """Return (signature_b64, key_id_used)."""
        ...


def compute_pdf_byterange_digest(pdf_bytes: bytes) -> str:
    """SHA-256 (hex) over the rendered PDF bytes.

    AMD-08 §Approach B: we sign the entire rendered PDF except the bytes that
    will hold the signature itself. Because we embed the signature in /Info
    (not as a /Sig entry inside the document), the signature insertion only
    appends to the cross-reference table — the body bytes signed here remain
    byte-identical after embedding. We therefore use a single-pass digest
    over the rendered PDF as the canonical byterange.

    Verifiers reproduce this by:
      1. Reading the original PDF
      2. Removing /X-Compliance-PDF-Byte-Signature and /X-Compliance-PDF-Byte-Sha256
         from /Info
      3. Re-saving with deterministic_id=True
      4. SHA-256 over the resulting bytes
      5. Verify the signature against that digest using the JWKS-resolved
         public key.
    """
    return hashlib.sha256(pdf_bytes).hexdigest()


async def sign_pdf_byterange(
    *,
    pdf_bytes: bytes,
    document_id: str,
    signing_client: SigningClient,
    key_id_hint: str | None = None,
) -> tuple[str, str, str]:
    """Drive the AMD-08 byterange signing round-trip.

    Returns (signature_b64, key_id_used, byterange_digest_hex).
    """
    if not pdf_bytes:
        raise ValueError("pdf_bytes must be non-empty")
    if not document_id:
        raise ValueError("document_id is required")
    digest_hex = compute_pdf_byterange_digest(pdf_bytes)
    sig_b64, key_id = await signing_client.sign_pdf_byterange(
        document_id=document_id,
        byterange_digest_hex=digest_hex,
        key_id_hint=key_id_hint,
    )
    if not sig_b64:
        raise RuntimeError("signing service returned empty signature")
    if not key_id:
        raise RuntimeError("signing service returned empty key_id")
    return sig_b64, key_id, digest_hex


# ── JWKS bundle helpers (AMD-04) ─────────────────────────────────────────────


class JwksClient(Protocol):
    async def fetch_jwks(self) -> dict[str, Any]:
        """Return the parsed JWKS document from the compliance service.

        Endpoint: GET /api/v1/compliance/.well-known/jwks.json
        Shape: {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "...", "x": "..."}]}
        """
        ...


async def fetch_jwks_bundle(client: JwksClient) -> dict[str, Any]:
    """Fetch the JWKS bundle for delivery alongside regulatory reports (AMD-04)."""
    jwks = await client.fetch_jwks()
    if not isinstance(jwks, dict) or "keys" not in jwks:
        raise RuntimeError("compliance service returned malformed JWKS")
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys:
        raise RuntimeError("compliance service returned empty JWKS keys list")
    return jwks


__all__ = [
    "SignatureSpec",
    "SigningClient",
    "JwksClient",
    "compute_pdf_byterange_digest",
    "sign_pdf_byterange",
    "fetch_jwks_bundle",
]
