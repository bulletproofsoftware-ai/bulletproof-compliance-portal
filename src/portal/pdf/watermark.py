"""Auditor watermark — visual overlay + XMP metadata (AMD-06).

The visual watermark is a CSS-driven diagonal red banner repeated on every
page. It is a deterrent, NOT a cryptographic protection — a determined
auditor can strip it with PDF tooling. Defense in depth comes from AMD-06's
XMP metadata embed (see metadata.embed_pdf_metadata) and the audit chain.

`WatermarkSpec` is the input model accepted by the renderer. Its
`watermark_id` field is computed automatically from `auditor_sub` and
`engagement_id` (AMD-13) so callers cannot forget it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from .cache import compute_watermark_id


class WatermarkSpec(BaseModel):
    """Inputs for a per-PDF auditor watermark.

    Required for every auditor-served PDF. Non-auditor PDFs MUST NOT receive a
    WatermarkSpec — the renderer enforces this.
    """

    model_config = ConfigDict(frozen=True)

    auditor_sub: str = Field(min_length=1, description="Auditor OIDC subject")
    engagement_id: str = Field(min_length=1, description="Engagement scope id")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp this PDF was generated",
    )
    scope_summary: str | None = Field(
        default=None,
        description=(
            "Optional short text describing engagement scope "
            "(e.g. 'AUDIT-2026-Q1, projects: foo,bar'). Rendered under identity."
        ),
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Engagement expiry (REQ-CPL-033 hard expiry). Embedded in XMP.",
    )

    @field_validator("auditor_sub", "engagement_id")
    @classmethod
    def _strip_and_check(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be blank")
        if "|" in v:
            # the | separator is reserved for watermark_id derivation
            raise ValueError("may not contain '|'")
        return v

    # ── Derived fields ──────────────────────────────────────────────────────
    @computed_field  # type: ignore[prop-decorator]
    @property
    def watermark_id(self) -> str:
        """Deterministic watermark id used in cache key + PDF /Metadata."""
        return compute_watermark_id(self.auditor_sub, self.engagement_id)

    # ── Helpers ─────────────────────────────────────────────────────────────
    def to_template_context(self) -> dict[str, Any]:
        """Plain dict the Jinja template receives.

        Keys are intentionally simple strings (no datetime objects) so the
        template never needs filters that could fail under sandboxing.
        """
        return {
            "auditor_sub": self.auditor_sub,
            "engagement_id": self.engagement_id,
            "watermark_id": self.watermark_id,
            "timestamp_iso": self.timestamp.astimezone(UTC).isoformat(
                timespec="seconds"
            ),
            "scope_summary": self.scope_summary or "",
            "expires_at_iso": (
                self.expires_at.astimezone(UTC).isoformat(timespec="seconds")
                if self.expires_at is not None
                else ""
            ),
        }

    def to_xmp_dict(self) -> dict[str, str]:
        """Strings written to PDF /Info dict by metadata.embed_pdf_metadata."""
        d = {
            "/X-Compliance-Auditor-Sub": self.auditor_sub,
            "/X-Compliance-Engagement-Id": self.engagement_id,
            "/X-Compliance-Exported-At": self.timestamp.astimezone(
                UTC
            ).isoformat(timespec="seconds"),
            "/X-Compliance-Watermark-Id": self.watermark_id,
        }
        if self.expires_at is not None:
            d["/X-Compliance-Engagement-Expires-At"] = self.expires_at.astimezone(
                UTC
            ).isoformat(timespec="seconds")
        if self.scope_summary:
            d["/X-Compliance-Scope-Summary"] = self.scope_summary
        return d


__all__ = ["WatermarkSpec"]
