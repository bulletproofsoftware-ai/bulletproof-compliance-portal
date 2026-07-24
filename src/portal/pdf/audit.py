"""Audit event emission for PDF generation.

Every PDF produced — successful or blocked — emits an audit event via the
compliance client. Failures to emit do NOT block the PDF response (matching
WI-17 audit middleware behavior); the event is logged locally and queued.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from ..logging import get_logger

logger = get_logger(__name__)


class AuditSink(Protocol):
    """Subset of `ComplianceClient` we depend on — keeps tests trivial."""

    async def record_audit_event(
        self,
        *,
        audit_type: str,
        user_id: str | None = None,
        classification: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any: ...


@dataclass(slots=True)
class PdfAuditEvent:
    """Structured event record for a PDF generation."""

    audit_type: str  # e.g., "pdf.export.audit_event" or "pdf.render.url_fetcher_blocked"
    component: str
    document_id: str | None
    user_sub: str
    user_role: str
    title: str
    classification: str = "internal"
    watermarked: bool = False
    signed: bool = False
    pades_signed: bool = False
    file_size: int = 0
    body_sha256: str | None = None
    pdf_byte_sha256: str | None = None
    watermark_id: str | None = None
    cache_hit: bool = False
    duration_ms: float | None = None
    blocked_url: str | None = None
    block_reason: str | None = None
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("audit_type", None)
        d.pop("user_sub", None)
        d.pop("classification", None)
        # ISO-format timestamps for transport
        d["occurred_at"] = self.occurred_at.astimezone(UTC).isoformat()
        # Strip empty optional fields so the payload stays compact
        return {k: v for k, v in d.items() if v not in (None, "", False) or k in {"watermarked", "signed", "cache_hit"}}


async def emit_pdf_audit_event(
    sink: AuditSink | None,
    event: PdfAuditEvent,
) -> bool:
    """Record an audit event. Returns True iff the sink accepted it.

    A None sink (e.g., during unit tests without a compliance client)
    becomes a local-log-only emit and returns False.
    """
    payload = event.to_payload()
    logger.info(
        "pdf.audit.event",
        audit_type=event.audit_type,
        user_id=event.user_sub,
        classification=event.classification,
        **payload,
    )

    if sink is None:
        return False

    try:
        await sink.record_audit_event(
            audit_type=event.audit_type,
            user_id=event.user_sub,
            classification=event.classification,
            payload=payload,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "pdf.audit.emit_failed",
            error=str(exc),
            audit_type=event.audit_type,
            user_id=event.user_sub,
        )
        return False


__all__ = ["PdfAuditEvent", "AuditSink", "emit_pdf_audit_event"]
