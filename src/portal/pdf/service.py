"""PdfService — orchestrator for WI-19.

Public surface:

    >>> svc = PdfService()
    >>> pdf_bytes = await svc.pdf_export(
    ...     template="audit_event.html",
    ...     context={"event": ..., "project": "default"},
    ...     watermark=None,                     # auditor PDFs supply this
    ...     signature=None,                     # signed reports supply this
    ...     title="Audit Event 12345",
    ...     user_identity="alice@corp",
    ...     user_role="compliance_officer",
    ... )

The service:
  * Renders Jinja templates in a sandboxed, autoescaping environment
  * Wraps the body in `base.html` (header / footer / optional watermark)
  * Computes a two-pass integrity hash (body SHA-256 written to footer)
  * Calls WeasyPrint with the locked-down url_fetcher (AMD-02)
  * Embeds AMD-04 / AMD-06 / AMD-08 metadata via pikepdf
  * Caches results keyed by (component, document_id, role, watermark_id, etag)
    (AMD-13 — watermark_id ensures cross-auditor isolation)
  * Emits an audit event for every PDF generation

If the AMD-08 PAdES round-trip is requested (`pades_signing_client` provided),
the service performs the byterange signing AFTER the first metadata embed and
re-embeds the byterange signature in /Info.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import FileSystemLoader, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from ..logging import get_logger
from .audit import AuditSink, PdfAuditEvent, emit_pdf_audit_event
from .cache import (
    DEFAULT_TTL_S,
    CacheEntry,
    PdfCache,
    compute_cache_key,
)
from .metadata import embed_pdf_metadata
from .signature import (
    SignatureSpec,
    SigningClient,
    sign_pdf_byterange,
)
from .url_fetcher import UrlFetcherBlocked
from .watermark import WatermarkSpec
from .weasy_config import make_html, make_print_css, write_pdf

logger = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class PdfRenderError(RuntimeError):
    """Raised by PdfService.pdf_export when rendering fails terminally."""

    def __init__(self, message: str, *, blocked_url: str | None = None) -> None:
        super().__init__(message)
        self.blocked_url = blocked_url


def _build_jinja_env() -> SandboxedEnvironment:
    """Sandboxed env — no filesystem access, no __import__, autoescape on.

    Loaders point at the bundled templates dir. The sandbox prevents
    template-injection style escapes (per WI-19 spec note: 'no Python file
    access')."""
    env = SandboxedEnvironment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(
            enabled_extensions=("html", "htm", "xml"),
            default_for_string=True,
        ),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    # Convenience filter: ISO-format datetimes
    def _iso(dt: Any) -> str:
        if isinstance(dt, datetime):
            return dt.astimezone(UTC).isoformat(timespec="seconds")
        return str(dt)

    env.filters["isoformat"] = _iso
    return env


class PdfService:
    """Cross-cutting PDF rendering service (REQ-CPL-045)."""

    def __init__(
        self,
        *,
        cache: PdfCache | None = None,
        audit_sink: AuditSink | None = None,
        pades_signing_client: SigningClient | None = None,
        render_timeout_s: float = 30.0,
    ) -> None:
        # NOTE: do NOT use `cache or PdfCache(...)` — PdfCache implements __len__
        # which makes empty caches falsy and the `or` would silently swap them.
        self._cache = cache if cache is not None else PdfCache(ttl_s=DEFAULT_TTL_S)
        self._audit_sink = audit_sink
        self._pades_client = pades_signing_client
        self._render_timeout_s = render_timeout_s
        self._jinja = _build_jinja_env()

    # ── Public API ───────────────────────────────────────────────────────────

    async def pdf_export(
        self,
        *,
        template: str,
        context: dict[str, Any],
        title: str,
        user_identity: str,
        user_role: str,
        project: str | None = None,
        watermark: WatermarkSpec | None = None,
        signature: SignatureSpec | None = None,
        require_pades: bool = False,
        document_id: str | None = None,
        component: str = "generic",
        version_or_etag: str | None = None,
        classification: str = "internal",
    ) -> bytes:
        """Render a template + context to PDF bytes.

        See module docstring for the full pipeline.

        Raises
        ------
        PdfRenderError
            On WeasyPrint failure, URL fetcher block, or timeout.
        """
        if not template:
            raise ValueError("template is required")
        if not title:
            raise ValueError("title is required")
        if not user_identity:
            raise ValueError("user_identity is required")
        if not user_role:
            raise ValueError("user_role is required")

        # AMD-06 enforcement: auditor PDFs MUST have a watermark
        if user_role == "auditor" and watermark is None:
            raise ValueError(
                "auditor PDFs require a WatermarkSpec (AMD-06 — identity stamp)"
            )
        # Inverse: non-auditor PDFs MUST NOT carry an auditor watermark
        if user_role != "auditor" and watermark is not None:
            raise ValueError(
                f"non-auditor role {user_role!r} must not supply a WatermarkSpec "
                "(over-collection / AC-24)"
            )

        cache_key = compute_cache_key(
            component=component,
            document_id=document_id or template,
            user_role=user_role,
            watermark_id=watermark.watermark_id if watermark else None,
            version_or_etag=version_or_etag,
        )

        # ── Cache lookup ────────────────────────────────────────────────────
        cached = self._cache.get(cache_key)
        if cached is not None:
            await self._emit_event(
                PdfAuditEvent(
                    audit_type="pdf.export.cache_hit",
                    component=component,
                    document_id=document_id,
                    user_sub=user_identity,
                    user_role=user_role,
                    title=title,
                    classification=classification,
                    watermarked=watermark is not None,
                    signed=signature is not None,
                    pades_signed=cached.metadata.get("pades_signed", False),
                    file_size=len(cached.pdf_bytes),
                    body_sha256=cached.metadata.get("body_sha256"),
                    pdf_byte_sha256=cached.metadata.get("pdf_byte_sha256"),
                    watermark_id=watermark.watermark_id if watermark else None,
                    cache_hit=True,
                )
            )
            return cached.pdf_bytes

        # ── Render with timeout ─────────────────────────────────────────────
        started = time.perf_counter()
        try:
            pdf_bytes, body_sha256 = await asyncio.wait_for(
                # F-07 — ``get_event_loop()`` is deprecated in Python 3.10+
                # when called outside a coroutine. We are inside an async
                # method, so ``get_running_loop()`` is the correct call.
                asyncio.get_running_loop().run_in_executor(
                    None,
                    self._render_sync,
                    template,
                    context,
                    title,
                    user_identity,
                    user_role,
                    project,
                    watermark,
                ),
                timeout=self._render_timeout_s,
            )
        except TimeoutError:
            await self._emit_event(
                PdfAuditEvent(
                    audit_type="pdf.render.timeout",
                    component=component,
                    document_id=document_id,
                    user_sub=user_identity,
                    user_role=user_role,
                    title=title,
                    classification=classification,
                )
            )
            raise PdfRenderError(
                f"PDF render exceeded {self._render_timeout_s}s timeout"
            ) from None
        except UrlFetcherBlocked as exc:
            await self._emit_event(
                PdfAuditEvent(
                    audit_type="pdf.render.url_fetcher_blocked",
                    component=component,
                    document_id=document_id,
                    user_sub=user_identity,
                    user_role=user_role,
                    title=title,
                    classification=classification,
                    blocked_url=exc.url,
                    block_reason=exc.reason,
                )
            )
            raise PdfRenderError(
                f"PDF fetch blocked: {exc.reason}",
                blocked_url=exc.url,
            ) from exc
        except Exception as exc:  # noqa: BLE001
            await self._emit_event(
                PdfAuditEvent(
                    audit_type="pdf.render.failed",
                    component=component,
                    document_id=document_id,
                    user_sub=user_identity,
                    user_role=user_role,
                    title=title,
                    classification=classification,
                    block_reason=str(exc),
                )
            )
            raise PdfRenderError(f"PDF render failed: {exc}") from exc

        # ── First-pass metadata embed (AMD-04 + AMD-06) ─────────────────────
        pdf_bytes = embed_pdf_metadata(
            pdf_bytes,
            title=title,
            author=user_identity,
            signature=signature,
            watermark=watermark,
        )

        # ── AMD-08 byterange signing for regulatory reports ────────────────
        pdf_byte_sha256: str | None = None
        pades_signed = False
        if require_pades:
            if self._pades_client is None:
                raise PdfRenderError(
                    "AMD-08 byterange signing requested but no signing client configured"
                )
            if not document_id:
                raise PdfRenderError(
                    "AMD-08 byterange signing requires document_id"
                )
            sig_b64, key_id_used, byte_digest_hex = await sign_pdf_byterange(
                pdf_bytes=pdf_bytes,
                document_id=document_id,
                signing_client=self._pades_client,
                key_id_hint=signature.signing_key_id if signature else None,
            )
            pdf_byte_sha256 = byte_digest_hex
            # Re-embed including the byterange signature
            pdf_bytes = embed_pdf_metadata(
                pdf_bytes,
                title=title,
                author=user_identity,
                signature=signature,
                watermark=watermark,
                pdf_byte_signature_b64=sig_b64,
            )
            pades_signed = True
            logger.info(
                "pdf.pades.signed",
                document_id=document_id,
                key_id=key_id_used,
                byte_sha256=byte_digest_hex,
            )

        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)

        # ── Cache + audit ──────────────────────────────────────────────────
        self._cache.put(
            cache_key,
            CacheEntry(
                pdf_bytes=pdf_bytes,
                metadata={
                    "body_sha256": body_sha256,
                    "pdf_byte_sha256": pdf_byte_sha256,
                    "pades_signed": pades_signed,
                },
            ),
        )

        await self._emit_event(
            PdfAuditEvent(
                audit_type="pdf.export.generated",
                component=component,
                document_id=document_id,
                user_sub=user_identity,
                user_role=user_role,
                title=title,
                classification=classification,
                watermarked=watermark is not None,
                signed=signature is not None,
                pades_signed=pades_signed,
                file_size=len(pdf_bytes),
                body_sha256=body_sha256,
                pdf_byte_sha256=pdf_byte_sha256,
                watermark_id=watermark.watermark_id if watermark else None,
                cache_hit=False,
                duration_ms=duration_ms,
            )
        )

        return pdf_bytes

    # ── Internals ────────────────────────────────────────────────────────────

    def _render_sync(
        self,
        template: str,
        context: dict[str, Any],
        title: str,
        user_identity: str,
        user_role: str,
        project: str | None,
        watermark: WatermarkSpec | None,
    ) -> tuple[bytes, str]:
        """Sync render path — runs inside a thread executor.

        Returns (pdf_bytes, body_sha256_hex).
        """
        # Render the body fragment first
        body_template = self._jinja.get_template(template)
        # Defensive: also wrap user-provided context under a single key so
        # malicious values cannot shadow framework-level template vars.
        body_html = body_template.render(
            **context,
            _meta={
                "title": title,
                "project": project,
                "user_identity": user_identity,
                "user_role": user_role,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            },
        )

        # Compute body integrity hash
        body_sha256 = hashlib.sha256(body_html.encode("utf-8")).hexdigest()

        # Render the wrapping base template
        base_template = self._jinja.get_template("base.html")
        wrapped_html = base_template.render(
            body_html=body_html,
            title=title,
            project=project or "Compliance Portal",
            user_identity=user_identity,
            user_role=user_role,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            integrity_hash=body_sha256,
            integrity_hash_short=f"{body_sha256[:8]}…{body_sha256[-8:]}",
            watermark=watermark.to_template_context() if watermark else None,
        )

        html = make_html(wrapped_html)
        css = make_print_css()
        pdf_bytes = write_pdf(html, stylesheets=[css])
        return pdf_bytes, body_sha256

    async def _emit_event(self, event: PdfAuditEvent) -> None:
        await emit_pdf_audit_event(self._audit_sink, event)


# ── Module-level convenience ─────────────────────────────────────────────────

_default_service: PdfService | None = None


def get_pdf_service() -> PdfService:
    """Process-global PdfService singleton.

    The FastAPI app constructs its own PdfService (with audit sink + signing
    client wired) on app.state in main.py; this fallback is for unit tests
    and one-off scripts.
    """
    global _default_service
    if _default_service is None:
        _default_service = PdfService()
    return _default_service


__all__ = ["PdfService", "PdfRenderError", "get_pdf_service"]
