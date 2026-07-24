"""WI-19 — PDF Export Service.

Cross-cutting service that renders any portal view as a PDF using WeasyPrint,
with security amendments per CISO architecture review:

    AMD-02 (CRITICAL)  fail-closed safe_url_fetcher (SSRF defense)
    AMD-04 (CRITICAL)  JWKS-aware signing (compliance service holds the key)
    AMD-06 (HIGH)      auditor identity embedded as PDF /Metadata XMP
    AMD-08 (HIGH)      PAdES-style byterange Ed25519 signing for regulatory reports
    AMD-13 (MEDIUM)    cache key includes watermark_id for cross-auditor isolation

Public API
----------

    >>> from portal.pdf import PdfService, WatermarkSpec, SignatureSpec
    >>> svc = PdfService()
    >>> pdf_bytes = await svc.pdf_export(
    ...     template="audit_event.html",
    ...     context={"event": ...},
    ...     title="Audit Event 12345",
    ...     user_identity="alice@corp",
    ...     user_role="compliance_officer",
    ... )

Component registration (for the generic /export/pdf/{component}/{id} route):

    >>> from portal.pdf import register_component
    >>> register_component("evidence_package", resolver=..., audit_event_type="evidence.pdf.exported")

Every PDF generation emits an audit event via the compliance client.
Auditor PDFs ALWAYS carry a watermark + /Metadata identity stamp.
"""

from .audit import PdfAuditEvent, emit_pdf_audit_event
from .cache import PdfCache, compute_cache_key, compute_watermark_id
from .metadata import embed_pdf_metadata
from .registry import (
    ComponentSpec,
    PdfComponentRegistry,
    get_default_registry,
    register_component,
)
from .service import PdfService, get_pdf_service
from .signature import SignatureSpec, sign_pdf_byterange
from .url_fetcher import STATIC_ROOT, UrlFetcherBlocked, safe_url_fetcher
from .watermark import WatermarkSpec

__all__ = [
    "PdfService",
    "get_pdf_service",
    "WatermarkSpec",
    "SignatureSpec",
    "PdfCache",
    "compute_cache_key",
    "compute_watermark_id",
    "safe_url_fetcher",
    "UrlFetcherBlocked",
    "STATIC_ROOT",
    "embed_pdf_metadata",
    "register_component",
    "ComponentSpec",
    "PdfComponentRegistry",
    "get_default_registry",
    "sign_pdf_byterange",
    "PdfAuditEvent",
    "emit_pdf_audit_event",
]
