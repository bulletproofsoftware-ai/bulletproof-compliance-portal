"""PDF /Info + XMP metadata writer (AMD-04 + AMD-06).

For every PDF served:
  - Title, Author, Producer, Creator, CreationDate, ModDate are populated
  - Auditor PDFs: write the four AMD-06 keys (Auditor-Sub, Engagement-Id,
    Exported-At, Watermark-Id), plus the optional Engagement-Expires-At and
    Scope-Summary
  - Signed PDFs: write the four AMD-04 keys (Signature, Signed-At, Signed-By,
    Key-Id), AND if the signature is over rendered bytes (regulatory report
    via PAdES-style byterange) write the AMD-08 keys (PDF-Byte-Signature,
    PDF-Byte-Sha256)

This module does NOT compute signatures. It only embeds the strings supplied
by the caller. Signature computation lives in signature.py and is performed
by the compliance service.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from io import BytesIO

import pikepdf

from .signature import SignatureSpec
from .watermark import WatermarkSpec

# Canonical /Info producer/creator strings — let downstream verifiers
# distinguish portal-generated PDFs from arbitrary uploads.
_PRODUCER = "Compliance Portal PDF Service (WI-19)"
_CREATOR = "Compliance Portal"


def _format_pdf_date(dt: datetime) -> str:
    """PDF-style date string: D:YYYYMMDDHHmmSS+00'00'."""
    dt = dt.astimezone(UTC)
    return "D:" + dt.strftime("%Y%m%d%H%M%S") + "+00'00'"


def embed_pdf_metadata(
    pdf_bytes: bytes,
    *,
    title: str,
    author: str,
    signature: SignatureSpec | None = None,
    watermark: WatermarkSpec | None = None,
    pdf_byte_signature_b64: str | None = None,
) -> bytes:
    """Embed /Info metadata into the PDF and return new bytes.

    Parameters
    ----------
    pdf_bytes
        Raw PDF produced by WeasyPrint.
    title
        Document title (becomes /Title).
    author
        Identity of the PDF requester (becomes /Author). For auditor PDFs the
        auditor sub is also embedded under /X-Compliance-Auditor-Sub via the
        watermark spec.
    signature
        Optional Ed25519 body signature obtained from the compliance service.
        Embedded under /X-Compliance-Signature et al. (AMD-04).
    watermark
        Optional WatermarkSpec — present for every auditor-served PDF.
        Triggers the AMD-06 keys.
    pdf_byte_signature_b64
        Optional. Present for regulatory reports that have completed the
        PAdES-style byterange round-trip (AMD-08). Embedded under
        /X-Compliance-PDF-Byte-Signature, alongside the SHA-256 of the
        bytes that were signed.
    """
    if not pdf_bytes:
        raise ValueError("pdf_bytes must be non-empty")
    if not title:
        raise ValueError("title is required")
    if not author:
        raise ValueError("author is required")

    now = datetime.now(UTC)

    with pikepdf.open(BytesIO(pdf_bytes)) as pdf:
        # Ensure docinfo exists
        with pdf.open_metadata(set_pikepdf_as_editor=False) as _xmp:
            # Touch metadata stream so pikepdf creates one if missing.
            pass

        info = pdf.docinfo
        info["/Title"] = title
        info["/Author"] = author
        info["/Producer"] = _PRODUCER
        info["/Creator"] = _CREATOR
        info["/CreationDate"] = _format_pdf_date(now)
        info["/ModDate"] = _format_pdf_date(now)

        # AMD-04 — Ed25519 body signature
        if signature is not None:
            sig_dict = signature.to_pdf_info_dict()
            for k, v in sig_dict.items():
                info[k] = v

        # AMD-06 — auditor identity (every auditor PDF)
        if watermark is not None:
            for k, v in watermark.to_xmp_dict().items():
                info[k] = v

        # AMD-08 — byterange signature for regulatory reports
        if pdf_byte_signature_b64:
            info["/X-Compliance-PDF-Byte-Signature"] = pdf_byte_signature_b64
            info["/X-Compliance-PDF-Byte-Sha256"] = hashlib.sha256(
                pdf_bytes
            ).hexdigest()

        out = BytesIO()
        pdf.save(out, deterministic_id=True)
        return out.getvalue()


def read_pdf_metadata(pdf_bytes: bytes) -> dict[str, str]:
    """Read all /Info entries — used by tests and by the verification CLI."""
    with pikepdf.open(BytesIO(pdf_bytes)) as pdf:
        info = pdf.docinfo
        out: dict[str, str] = {}
        for k, v in info.items():
            try:
                out[str(k)] = str(v)
            except Exception:  # noqa: BLE001
                continue
        return out


__all__ = ["embed_pdf_metadata", "read_pdf_metadata"]
