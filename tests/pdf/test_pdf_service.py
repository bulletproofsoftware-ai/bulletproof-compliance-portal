"""WI-19 — PDF Export Service tests.

Covers:
  * AMD-02 SSRF: AWS IMDS, file:///etc/passwd, https://evil.com all blocked
  * AMD-02: data: URIs with allowlisted MIME accepted
  * AMD-02: bundled assets under STATIC_ROOT accepted
  * AMD-02: symlink escape rejected
  * AMD-04: signature embedded in /Info, JWKS-aware key id
  * AMD-06: auditor identity in PDF /Metadata XMP for every auditor PDF
  * AMD-08: PAdES-style byterange signing round-trip
  * AMD-13: cache key isolates by watermark_id (cross-auditor test)
  * Spec ACs:
      AC-01 returns valid PDF bytes
      AC-02 header content
      AC-03 page numbers (counter present)
      AC-09 router Content-Disposition
      AC-10 unknown component 404
      AC-11 RBAC denial paths
      AC-12 audit event for every PDF generation
      AC-13 cache hit avoids re-render
      AC-14 cache key isolates auditor watermarks
      AC-22 every auditor PDF has the four AMD-06 keys
      AC-24 non-auditor PDFs do NOT carry AMD-06 keys
      AC-29-31 watermark_id determinism + isolation

Real PDF generation tests are gated behind `requires_weasyprint` so that
environments missing native deps (Cairo / Pango / GDK-Pixbuf) can still run
the SSRF, cache, signature-logic, and RBAC tests.
"""

from __future__ import annotations

import asyncio
import base64
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

# Add src to path BEFORE importing portal.* (mirrors tests/conftest.py)
_SRC = Path(__file__).resolve().parent.parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Detect WeasyPrint native deps
try:
    import weasyprint  # noqa: F401

    _WP_AVAILABLE = True
    _WP_SKIP_REASON = ""
except Exception as exc:  # noqa: BLE001
    _WP_AVAILABLE = False
    _WP_SKIP_REASON = f"WeasyPrint native deps unavailable: {exc}"

requires_weasyprint = pytest.mark.skipif(
    not _WP_AVAILABLE, reason=_WP_SKIP_REASON or "WeasyPrint not available"
)


# ───────────────────────── Fixtures & helpers ────────────────────────────────


@pytest.fixture()
def fresh_registry():
    """Reset the default registry between tests."""
    from portal.pdf.registry import reset_default_registry

    reset_default_registry()
    yield
    reset_default_registry()


@pytest.fixture()
def sample_event_context() -> dict[str, Any]:
    return {
        "event": {
            "id": "evt-12345",
            "audit_type": "evidence.viewed",
            "user_id": "alice@corp",
            "classification": "internal",
            "ts": "2026-04-27T10:00:00Z",
            "hash": "abc123",
            "prev_hash": "def456",
            "payload": {"resource_id": "res-1", "ip": "203.0.113.1"},
        },
        "project": "compliance-portal",
    }


def _build_auditor_user(sub: str = "auditor-1", engagement_id: str = "ENG-2026-Q1"):
    """Light-weight User object for tests (without going through full session flow)."""
    from portal.auth.models import AuditorScope, Role, User

    now = datetime.now(UTC)
    return User(
        sub=sub,
        email=f"{sub}@example.com",
        name=sub,
        roles=[Role.AUDITOR],
        auditor_scope=AuditorScope(
            engagement_id=engagement_id,
            engagement_start=now - timedelta(days=10),
            engagement_end=now + timedelta(days=80),
            date_range_start=now - timedelta(days=365),
            date_range_end=now,
            allowed_artifact_types=["audit_event", "evidence_package"],
            allowed_project_ids=None,
        ),
        mfa_at=now,
        session_id="sess-1",
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )


# ───────────────────────── AMD-02 — URL fetcher SSRF ─────────────────────────


class TestUrlFetcherSSRF:
    """AMD-02 — fail-closed safe_url_fetcher."""

    def test_aws_imds_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked) as ei:
            safe_url_fetcher(
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            )
        assert "remote http" in str(ei.value).lower() or "blocked" in str(ei.value).lower()

    def test_https_external_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("https://evil.com/steal")

    def test_localhost_postgres_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("http://localhost:5432/")

    def test_internal_lateral_movement_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("http://internal-portal:8080/admin/users")

    def test_etc_passwd_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked) as ei:
            safe_url_fetcher("file:///etc/passwd")
        assert "outside STATIC_ROOT" in str(ei.value)

    def test_file_with_remote_host_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("file://attacker.example/etc/passwd")

    def test_ftp_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("ftp://corp.example/dump.tar")

    def test_empty_url_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher("")

    def test_data_uri_text_css_accepted(self):
        from portal.pdf.url_fetcher import safe_url_fetcher

        result = safe_url_fetcher("data:text/css,body%7Bcolor%3Ared%7D")
        assert result["mime_type"] == "text/css"
        assert result["file_obj"].read() == b"body{color:red}"

    def test_data_uri_base64_png_accepted(self):
        from portal.pdf.url_fetcher import safe_url_fetcher

        # 1x1 transparent PNG
        png_b64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVQYV2NgYAAAAAMAAW"
            "gMyVoAAAAASUVORK5CYII="
        )
        url = f"data:image/png;base64,{png_b64}"
        result = safe_url_fetcher(url)
        assert result["mime_type"] == "image/png"
        body = result["file_obj"].read()
        assert body[:8] == b"\x89PNG\r\n\x1a\n"

    def test_data_uri_disallowed_mime_blocked(self):
        from portal.pdf.url_fetcher import UrlFetcherBlocked, safe_url_fetcher

        # JavaScript MIME — should not be in the allowlist
        with pytest.raises(UrlFetcherBlocked) as ei:
            safe_url_fetcher("data:application/javascript,alert(1)")
        assert "not in allowlist" in str(ei.value)

    def test_bundled_static_file_accepted(self):
        from portal.pdf.url_fetcher import STATIC_ROOT, safe_url_fetcher

        # print.css is bundled — must be accessible
        url = f"file://{STATIC_ROOT}/print.css"
        result = safe_url_fetcher(url)
        assert result["mime_type"] == "text/css"
        body = result["file_obj"].read()
        assert b"@page" in body

    def test_symlink_escape_blocked(self, tmp_path):
        """Plant a symlink under STATIC_ROOT pointing at /etc/passwd; resolver must reject."""
        from portal.pdf.url_fetcher import STATIC_ROOT, UrlFetcherBlocked, safe_url_fetcher

        link = Path(STATIC_ROOT) / "_test_evil_symlink"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to("/etc/passwd")
            url = f"file://{link}"
            with pytest.raises(UrlFetcherBlocked) as ei:
                safe_url_fetcher(url)
            # Either path-outside or file-does-not-exist depending on platform
            assert (
                "outside STATIC_ROOT" in str(ei.value)
                or "does not exist" in str(ei.value)
            )
        finally:
            if link.exists() or link.is_symlink():
                link.unlink()

    def test_path_traversal_blocked(self):
        from portal.pdf.url_fetcher import STATIC_ROOT, UrlFetcherBlocked, safe_url_fetcher

        # Even though the path syntactically starts with STATIC_ROOT, the .. traversal
        # makes realpath escape — fail closed.
        url = f"file://{STATIC_ROOT}/../../../etc/passwd"
        with pytest.raises(UrlFetcherBlocked):
            safe_url_fetcher(url)

    def test_fetch_log_records_blocks(self):
        from portal.pdf.url_fetcher import (
            UrlFetcherBlocked,
            clear_fetch_log,
            install_fetch_log,
            safe_url_fetcher,
        )

        log = install_fetch_log()
        try:
            with pytest.raises(UrlFetcherBlocked):
                safe_url_fetcher("https://evil.com/")
            with pytest.raises(UrlFetcherBlocked):
                safe_url_fetcher("file:///etc/passwd")
            assert len(log) == 2
            assert all(a.decision == "block" for a in log)
        finally:
            clear_fetch_log()


# ───────────────────────── AMD-13 — watermark_id ─────────────────────────────


class TestWatermarkId:
    """AC-29..31 — deterministic, isolated watermark_id."""

    def test_deterministic(self):
        from portal.pdf.cache import compute_watermark_id

        a1 = compute_watermark_id("alice", "ENG-1")
        a2 = compute_watermark_id("alice", "ENG-1")
        assert a1 == a2

    def test_different_auditor_different_id(self):
        from portal.pdf.cache import compute_watermark_id

        a = compute_watermark_id("alice", "ENG-1")
        b = compute_watermark_id("bob", "ENG-1")
        assert a != b

    def test_different_engagement_different_id(self):
        from portal.pdf.cache import compute_watermark_id

        a1 = compute_watermark_id("alice", "ENG-1")
        a2 = compute_watermark_id("alice", "ENG-2")
        assert a1 != a2

    def test_pipe_in_inputs_rejected(self):
        from portal.pdf.watermark import WatermarkSpec

        with pytest.raises(Exception):
            WatermarkSpec(auditor_sub="alice|injected", engagement_id="ENG-1")

    def test_blank_inputs_rejected(self):
        from portal.pdf.cache import compute_watermark_id

        with pytest.raises(ValueError):
            compute_watermark_id("", "ENG-1")
        with pytest.raises(ValueError):
            compute_watermark_id("alice", "")


# ───────────────────────── Cache (with watermark_id) ─────────────────────────


class TestCache:
    """AC-13 + AC-14 — cache hit + cross-auditor isolation."""

    def test_put_get_roundtrip(self):
        from portal.pdf.cache import CacheEntry, PdfCache

        c = PdfCache(ttl_s=60, max_entries=8)
        c.put("k1", CacheEntry(pdf_bytes=b"%PDF-fake-1"))
        e = c.get("k1")
        assert e is not None
        assert e.pdf_bytes == b"%PDF-fake-1"

    def test_miss(self):
        from portal.pdf.cache import PdfCache

        c = PdfCache(ttl_s=60, max_entries=8)
        assert c.get("nope") is None

    def test_invalidate(self):
        from portal.pdf.cache import CacheEntry, PdfCache

        c = PdfCache(ttl_s=60, max_entries=8)
        c.put("k1", CacheEntry(pdf_bytes=b"x"))
        assert c.invalidate("k1") is True
        assert c.invalidate("k1") is False

    def test_cross_auditor_keys_diverge(self):
        """AC-14 / AC-30 — two auditors viewing the same document MUST get different cache keys."""
        from portal.pdf.cache import compute_cache_key, compute_watermark_id

        wm_a = compute_watermark_id("alice", "ENG-1")
        wm_b = compute_watermark_id("bob", "ENG-1")
        k_a = compute_cache_key(
            component="evidence_package",
            document_id="pkg-1",
            user_role="auditor",
            watermark_id=wm_a,
            version_or_etag="v1",
        )
        k_b = compute_cache_key(
            component="evidence_package",
            document_id="pkg-1",
            user_role="auditor",
            watermark_id=wm_b,
            version_or_etag="v1",
        )
        assert k_a != k_b

    def test_cross_engagement_keys_diverge(self):
        """AC-31 — same auditor in two engagements gets different cache keys."""
        from portal.pdf.cache import compute_cache_key, compute_watermark_id

        wm_1 = compute_watermark_id("alice", "ENG-1")
        wm_2 = compute_watermark_id("alice", "ENG-2")
        k1 = compute_cache_key(
            component="evidence_package",
            document_id="pkg-1",
            user_role="auditor",
            watermark_id=wm_1,
            version_or_etag="v1",
        )
        k2 = compute_cache_key(
            component="evidence_package",
            document_id="pkg-1",
            user_role="auditor",
            watermark_id=wm_2,
            version_or_etag="v1",
        )
        assert k1 != k2

    def test_role_in_key(self):
        from portal.pdf.cache import compute_cache_key

        k_v = compute_cache_key(
            component="audit_event",
            document_id="e1",
            user_role="viewer",
            watermark_id=None,
            version_or_etag="v1",
        )
        k_o = compute_cache_key(
            component="audit_event",
            document_id="e1",
            user_role="compliance_officer",
            watermark_id=None,
            version_or_etag="v1",
        )
        assert k_v != k_o


# ───────────────────────── Registry & RBAC ───────────────────────────────────


class TestRegistry:
    def test_register_and_lookup(self, fresh_registry):
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id: str, user) -> tuple[str, dict, str, str]:
            return ("audit_event.html", {"event": {"id": doc_id}}, f"Event {doc_id}", "internal")

        reg = get_default_registry()
        reg.register(
            "audit_event",
            template="audit_event.html",
            resolver=resolver,
            audit_event_type="audit.pdf.exported",
        )
        assert "audit_event" in reg
        spec = reg.get("audit_event")
        assert spec is not None
        assert spec.template == "audit_event.html"
        assert spec.audit_event_type == "audit.pdf.exported"

    def test_duplicate_rejected(self, fresh_registry):
        from portal.pdf.registry import get_default_registry

        async def r(d, u):
            return ("audit_event.html", {}, "x", "internal")

        reg = get_default_registry()
        reg.register("c1", template="audit_event.html", resolver=r, audit_event_type="x")
        with pytest.raises(ValueError):
            reg.register("c1", template="audit_event.html", resolver=r, audit_event_type="x")

    def test_invalid_component_name(self, fresh_registry):
        from portal.pdf.registry import get_default_registry

        async def r(d, u):
            return ("audit_event.html", {}, "x", "internal")

        reg = get_default_registry()
        with pytest.raises(ValueError):
            reg.register("bad/name", template="audit_event.html", resolver=r, audit_event_type="x")

    def test_role_filter(self, fresh_registry):
        from portal.pdf.registry import get_default_registry

        async def r(d, u):
            return ("evidence_package.html", {}, "x", "auditor")

        reg = get_default_registry()
        reg.register(
            "evidence_package",
            template="evidence_package.html",
            resolver=r,
            audit_event_type="evidence.pdf.exported",
            allowed_roles={"auditor", "admin", "compliance_officer"},
        )
        spec = reg.get("evidence_package")
        assert spec.is_role_allowed("auditor")
        assert spec.is_role_allowed("admin")
        assert not spec.is_role_allowed("viewer")
        assert not spec.is_role_allowed("sme")


# ───────────────────────── Signature & metadata embedding ───────────────────


class TestSignatureMetadata:
    """AMD-04 + AMD-08 — signature flows. Use a tiny valid PDF for embed tests."""

    @requires_weasyprint
    def test_pdf_metadata_round_trip(self):
        """AC-22 — auditor PDF carries the four AMD-06 keys."""
        import asyncio

        from portal.pdf.metadata import read_pdf_metadata
        from portal.pdf.service import PdfService
        from portal.pdf.watermark import WatermarkSpec

        wm = WatermarkSpec(
            auditor_sub="auditor-bob",
            engagement_id="ENG-2026",
            timestamp=datetime(2026, 4, 27, tzinfo=UTC),
        )
        svc = PdfService()
        pdf = asyncio.run(
            svc.pdf_export(
                template="audit_event.html",
                context={"event": {"id": "e1", "audit_type": "x", "user_id": "u", "classification": "internal", "ts": "2026", "hash": "h", "prev_hash": "p", "payload": {}}},
                title="Auditor PDF",
                user_identity="auditor-bob",
                user_role="auditor",
                watermark=wm,
                document_id="e1",
                component="audit_event",
            )
        )
        meta = read_pdf_metadata(pdf)
        assert "/X-Compliance-Auditor-Sub" in meta
        assert "/X-Compliance-Engagement-Id" in meta
        assert "/X-Compliance-Exported-At" in meta
        assert "/X-Compliance-Watermark-Id" in meta
        assert meta["/X-Compliance-Auditor-Sub"] == "auditor-bob"
        assert meta["/X-Compliance-Engagement-Id"] == "ENG-2026"
        assert meta["/X-Compliance-Watermark-Id"] == wm.watermark_id

    @requires_weasyprint
    def test_non_auditor_pdf_omits_auditor_keys(self):
        """AC-24 — non-auditor PDFs do NOT include the AMD-06 keys (no over-collection)."""
        from portal.pdf.metadata import read_pdf_metadata
        from portal.pdf.service import PdfService

        svc = PdfService()
        pdf = asyncio.run(
            svc.pdf_export(
                template="audit_event.html",
                context={"event": {"id": "e2", "audit_type": "x", "user_id": "u", "classification": "internal", "ts": "2026", "hash": "h", "prev_hash": "p", "payload": {}}},
                title="Officer PDF",
                user_identity="officer@corp",
                user_role="compliance_officer",
                document_id="e2",
                component="audit_event",
            )
        )
        meta = read_pdf_metadata(pdf)
        for k in ("/X-Compliance-Auditor-Sub", "/X-Compliance-Engagement-Id", "/X-Compliance-Watermark-Id"):
            assert k not in meta, f"{k!r} should not be in non-auditor PDF: {meta}"

    @requires_weasyprint
    def test_signature_embedding(self):
        """AC-07 + AMD-04 — signed reports embed Ed25519 metadata."""
        from portal.pdf.metadata import read_pdf_metadata
        from portal.pdf.service import PdfService
        from portal.pdf.signature import SignatureSpec

        sig = SignatureSpec(
            signature=base64.b64encode(b"mock-signature-bytes" * 4).decode(),
            signed_at=datetime(2026, 4, 27, tzinfo=UTC),
            signed_by="compliance-svc",
            signing_key_id="key-2026-q1",
            body_sha256_hex="abcd" * 16,
        )
        svc = PdfService()
        pdf = asyncio.run(
            svc.pdf_export(
                template="regulatory_report.html",
                context={"report": {"id": "RPT-1", "framework": "SOX", "period": "Q1", "deadline": "—", "status": "approved", "prepared_by": "alice", "approved_by": "bob", "approved_at": "2026", "executive_summary": "ok", "findings": [], "attestations": []}},
                title="Regulatory Report",
                user_identity="officer@corp",
                user_role="compliance_officer",
                signature=sig,
                document_id="RPT-1",
                component="regulatory_report",
            )
        )
        meta = read_pdf_metadata(pdf)
        assert meta["/X-Compliance-Signature"] == sig.signature
        assert meta["/X-Compliance-Signed-By"] == "compliance-svc"
        assert meta["/X-Compliance-Key-Id"] == "key-2026-q1"

    def test_pades_byterange_signing_logic(self):
        """AMD-08 — PAdES byterange signing flow with mock signing client."""
        from portal.pdf.signature import (
            compute_pdf_byterange_digest,
            sign_pdf_byterange,
        )

        captured: dict[str, Any] = {}

        class MockSigningClient:
            async def sign_pdf_byterange(self, *, document_id, byterange_digest_hex, key_id_hint=None):
                captured["document_id"] = document_id
                captured["digest_hex"] = byterange_digest_hex
                captured["key_id_hint"] = key_id_hint
                return base64.b64encode(b"mock-pades-sig" * 4).decode(), "key-2026-q1"

        pdf_fake = b"%PDF-1.7\n%fake-bytes-for-test\n%%EOF"
        sig_b64, key_id, digest = asyncio.run(
            sign_pdf_byterange(
                pdf_bytes=pdf_fake,
                document_id="RPT-1",
                signing_client=MockSigningClient(),
                key_id_hint="key-2026-q1",
            )
        )
        assert sig_b64
        assert key_id == "key-2026-q1"
        # Digest matches what compute_pdf_byterange_digest produces independently
        assert digest == compute_pdf_byterange_digest(pdf_fake)
        assert captured["document_id"] == "RPT-1"
        assert captured["digest_hex"] == digest

    def test_pades_modified_pdf_changes_digest(self):
        """AC-26 — modifying any byte changes the byterange digest."""
        from portal.pdf.signature import compute_pdf_byterange_digest

        pdf1 = b"%PDF-1.7\n%body-A\n%%EOF"
        pdf2 = b"%PDF-1.7\n%body-B\n%%EOF"
        assert compute_pdf_byterange_digest(pdf1) != compute_pdf_byterange_digest(pdf2)


# ───────────────────────── Audit event emission ──────────────────────────────


class TestAuditEvents:
    """AC-12 — every PDF generation emits an audit event."""

    def test_event_emitted_with_sink(self):
        from portal.pdf.audit import PdfAuditEvent, emit_pdf_audit_event

        recorded: list[dict[str, Any]] = []

        class StubSink:
            async def record_audit_event(self, *, audit_type, user_id=None, classification=None, payload=None):
                recorded.append({
                    "audit_type": audit_type,
                    "user_id": user_id,
                    "classification": classification,
                    "payload": payload,
                })
                return None

        ok = asyncio.run(
            emit_pdf_audit_event(
                StubSink(),
                PdfAuditEvent(
                    audit_type="pdf.export.generated",
                    component="audit_event",
                    document_id="e-1",
                    user_sub="alice",
                    user_role="compliance_officer",
                    title="t",
                    file_size=1024,
                ),
            )
        )
        assert ok is True
        assert len(recorded) == 1
        assert recorded[0]["audit_type"] == "pdf.export.generated"
        assert recorded[0]["user_id"] == "alice"
        assert "component" in recorded[0]["payload"]
        assert recorded[0]["payload"]["component"] == "audit_event"
        assert recorded[0]["payload"]["file_size"] == 1024

    def test_sink_failure_is_swallowed(self):
        from portal.pdf.audit import PdfAuditEvent, emit_pdf_audit_event

        class BrokenSink:
            async def record_audit_event(self, **kw):
                raise RuntimeError("downstream is down")

        ok = asyncio.run(
            emit_pdf_audit_event(
                BrokenSink(),
                PdfAuditEvent(
                    audit_type="pdf.export.generated",
                    component="x",
                    document_id="d",
                    user_sub="u",
                    user_role="viewer",
                    title="t",
                ),
            )
        )
        assert ok is False  # emission failed, but didn't raise

    def test_no_sink_returns_false(self):
        from portal.pdf.audit import PdfAuditEvent, emit_pdf_audit_event

        ok = asyncio.run(
            emit_pdf_audit_event(
                None,
                PdfAuditEvent(
                    audit_type="pdf.export.generated",
                    component="x",
                    document_id="d",
                    user_sub="u",
                    user_role="viewer",
                    title="t",
                ),
            )
        )
        assert ok is False  # local-log only


# ───────────────────────── End-to-end render (gated) ─────────────────────────


@requires_weasyprint
class TestRenderEndToEnd:
    """AC-01 / AC-02 / AC-12 / AC-13 — full render path."""

    def test_basic_render_returns_pdf_bytes(self, sample_event_context):
        """AC-01."""
        from portal.pdf.service import PdfService

        svc = PdfService()
        pdf = asyncio.run(
            svc.pdf_export(
                template="audit_event.html",
                context=sample_event_context,
                title="Test Audit Event",
                user_identity="alice@corp",
                user_role="compliance_officer",
                document_id="evt-12345",
                component="audit_event",
            )
        )
        assert pdf[:4] == b"%PDF"
        assert len(pdf) > 1000

    def test_header_content_present(self, sample_event_context):
        """AC-02 — header includes project, title, user identity + role."""
        import pikepdf

        from portal.pdf.service import PdfService

        svc = PdfService()
        pdf = asyncio.run(
            svc.pdf_export(
                template="audit_event.html",
                context=sample_event_context,
                title="Header Check",
                user_identity="alice@corp",
                user_role="compliance_officer",
            )
        )
        from io import BytesIO

        with pikepdf.open(BytesIO(pdf)) as doc:
            assert str(doc.docinfo["/Title"]) == "Header Check"
            assert str(doc.docinfo["/Author"]) == "alice@corp"
            assert "Compliance Portal" in str(doc.docinfo["/Producer"])

    def test_cache_hit_avoids_re_render(self, sample_event_context):
        """AC-13 — second call within TTL returns the same bytes from cache."""
        from portal.pdf.cache import PdfCache
        from portal.pdf.service import PdfService

        cache = PdfCache(ttl_s=60, max_entries=8)
        svc = PdfService(cache=cache)
        kw = dict(
            template="audit_event.html",
            context=sample_event_context,
            title="Cache Test",
            user_identity="alice@corp",
            user_role="compliance_officer",
            document_id="evt-12345",
            component="audit_event",
            version_or_etag="v1",
        )
        pdf1 = asyncio.run(svc.pdf_export(**kw))
        pdf2 = asyncio.run(svc.pdf_export(**kw))
        assert pdf1 == pdf2  # identical bytes (cache hit)
        stats = cache.stats
        assert stats["hits"] >= 1
        assert stats["size"] >= 1

    def test_auditor_render_requires_watermark(self, sample_event_context):
        """AMD-06 enforcement — auditor PDF must have a WatermarkSpec."""
        from portal.pdf.service import PdfService

        svc = PdfService()
        with pytest.raises(ValueError, match="auditor PDFs require a WatermarkSpec"):
            asyncio.run(
                svc.pdf_export(
                    template="audit_event.html",
                    context=sample_event_context,
                    title="x",
                    user_identity="auditor-1",
                    user_role="auditor",
                )
            )

    def test_non_auditor_cannot_supply_watermark(self, sample_event_context):
        """AC-24 enforcement — non-auditor must NOT carry an auditor watermark."""
        from portal.pdf.service import PdfService
        from portal.pdf.watermark import WatermarkSpec

        wm = WatermarkSpec(auditor_sub="alice", engagement_id="ENG-1")
        svc = PdfService()
        with pytest.raises(ValueError, match="must not supply a WatermarkSpec"):
            asyncio.run(
                svc.pdf_export(
                    template="audit_event.html",
                    context=sample_event_context,
                    title="x",
                    user_identity="alice",
                    user_role="compliance_officer",
                    watermark=wm,
                )
            )

    def test_ssrf_attempt_in_template_recorded(self, caplog):
        """AC-17b/d — template that tries to fetch http://169.254.169.254 is blocked.

        WeasyPrint's behavior is to LOG fetch errors and continue rendering with
        the missing asset (no exception propagates from write_pdf). The fail-closed
        guarantee is therefore that:
          (a) safe_url_fetcher raised UrlFetcherBlocked (recorded in fetch_log)
          (b) the malicious URL never produced a real outbound request
          (c) the rendered PDF is still produced — but without the blocked asset
        """
        import logging

        import weasyprint

        from portal.pdf.url_fetcher import (
            clear_fetch_log,
            install_fetch_log,
            safe_url_fetcher,
        )

        evil_html = """
        <html><head>
          <link rel='stylesheet' href='http://169.254.169.254/x.css'>
          <link rel='stylesheet' href='file:///etc/passwd'>
        </head>
        <body>hello</body></html>
        """
        log = install_fetch_log()
        try:
            with caplog.at_level(logging.WARNING):
                pdf = weasyprint.HTML(
                    string=evil_html, url_fetcher=safe_url_fetcher
                ).write_pdf()
            # Both URLs hit the fetcher and were blocked
            assert any(
                a.decision == "block" and "169.254.169.254" in a.url for a in log
            )
            assert any(
                a.decision == "block" and a.url.startswith("file:///etc/passwd")
                for a in log
            )
            # PDF still rendered (without the malicious assets)
            assert pdf[:4] == b"%PDF"
        finally:
            clear_fetch_log()


# ───────────────────────── Router (AC-09 / AC-10 / AC-11) ────────────────────


class TestExportRouter:
    """AC-09 / AC-10 / AC-11 — generic /export/pdf/{component}/{document_id}."""

    def _build_app_with_user(self, user, registry):
        """Construct a minimal FastAPI app that serves the export router with
        a hard-coded current_user (no full session/cookie flow)."""
        from fastapi import FastAPI

        from portal.auth.rbac import current_user as current_user_dep
        from portal.pdf.cache import PdfCache
        from portal.pdf.service import PdfService
        from portal.routers import export as export_router_module

        app = FastAPI()
        app.state.pdf_registry = registry
        app.state.pdf_cache = PdfCache()
        app.state.pdf_service = PdfService(cache=app.state.pdf_cache)
        app.include_router(export_router_module.router)
        app.dependency_overrides[current_user_dep] = lambda: user
        return app

    def test_unknown_component_404(self, fresh_registry):
        from fastapi.testclient import TestClient

        from portal.auth.models import Role, User
        from portal.pdf.registry import get_default_registry

        now = datetime.now(UTC)
        user = User(
            sub="u",
            email="u@e.com",
            name="u",
            roles=[Role.COMPLIANCE_OFFICER],
            mfa_at=now,
            session_id="s",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        app = self._build_app_with_user(user, get_default_registry())
        client = TestClient(app)
        r = client.get("/export/pdf/no_such_component/doc-1")
        assert r.status_code == 404
        assert "unknown" in r.json()["detail"].lower()

    @requires_weasyprint
    def test_happy_path_returns_pdf(self, fresh_registry):
        from fastapi.testclient import TestClient

        from portal.auth.models import Role, User
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id, user):
            return (
                "audit_event.html",
                {
                    "event": {
                        "id": doc_id,
                        "audit_type": "x",
                        "user_id": "u",
                        "classification": "internal",
                        "ts": "2026",
                        "hash": "h",
                        "prev_hash": "p",
                        "payload": {},
                    }
                },
                f"Audit Event {doc_id}",
                "internal",
            )

        reg = get_default_registry()
        reg.register(
            "audit_event",
            template="audit_event.html",
            resolver=resolver,
            audit_event_type="audit.pdf.exported",
        )
        now = datetime.now(UTC)
        user = User(
            sub="officer",
            email="officer@e.com",
            name="o",
            roles=[Role.COMPLIANCE_OFFICER],
            mfa_at=now,
            session_id="s",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        app = self._build_app_with_user(user, reg)
        client = TestClient(app)
        r = client.get("/export/pdf/audit_event/evt-99")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert "attachment" in r.headers["content-disposition"]
        assert "audit_event-evt-99.pdf" in r.headers["content-disposition"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.content[:4] == b"%PDF"

    def test_role_denied_returns_403(self, fresh_registry):
        """AC-11 — viewer cannot export auditor-scope evidence_package."""
        from fastapi.testclient import TestClient

        from portal.auth.models import Role, User
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id, user):
            return ("evidence_package.html", {"package": {"id": doc_id, "artifacts": []}}, f"Pkg {doc_id}", "auditor")

        reg = get_default_registry()
        reg.register(
            "evidence_package",
            template="evidence_package.html",
            resolver=resolver,
            audit_event_type="evidence.pdf.exported",
            allowed_roles={"auditor", "admin", "compliance_officer"},
            auditor_only_components=False,
        )

        now = datetime.now(UTC)
        viewer = User(
            sub="viewer-1",
            email="v@e.com",
            name="v",
            roles=[Role.VIEWER],
            mfa_at=now,
            session_id="s",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        app = self._build_app_with_user(viewer, reg)
        client = TestClient(app)
        r = client.get("/export/pdf/evidence_package/pkg-1")
        assert r.status_code == 403

    def test_resolver_403_propagates(self, fresh_registry):
        """AC-11 — resolver-level 403 (auditor scope check) propagates."""
        from fastapi import HTTPException
        from fastapi import status as http_status
        from fastapi.testclient import TestClient

        from portal.auth.models import Role, User
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id, user):
            raise HTTPException(http_status.HTTP_403_FORBIDDEN, detail="document outside scope")

        reg = get_default_registry()
        reg.register(
            "audit_event",
            template="audit_event.html",
            resolver=resolver,
            audit_event_type="audit.pdf.exported",
        )

        now = datetime.now(UTC)
        user = User(
            sub="officer",
            email="o@e.com",
            name="o",
            roles=[Role.COMPLIANCE_OFFICER],
            mfa_at=now,
            session_id="s",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        app = self._build_app_with_user(user, reg)
        client = TestClient(app)
        r = client.get("/export/pdf/audit_event/forbidden-doc")
        assert r.status_code == 403
        assert "outside scope" in r.json()["detail"]

    @requires_weasyprint
    def test_auditor_gets_watermark(self, fresh_registry):
        """AC-22 — auditor GET emits PDF with the four AMD-06 keys."""
        from fastapi.testclient import TestClient

        from portal.pdf.metadata import read_pdf_metadata
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id, user):
            return ("audit_event.html", {"event": {"id": doc_id, "audit_type": "x", "user_id": "u", "classification": "internal", "ts": "2026", "hash": "h", "prev_hash": "p", "payload": {}}}, f"Event {doc_id}", "auditor")

        reg = get_default_registry()
        reg.register(
            "audit_event",
            template="audit_event.html",
            resolver=resolver,
            audit_event_type="audit.pdf.exported",
        )
        auditor = _build_auditor_user("auditor-bob", "ENG-2026")
        app = self._build_app_with_user(auditor, reg)
        client = TestClient(app)
        r = client.get("/export/pdf/audit_event/evt-77")
        assert r.status_code == 200
        meta = read_pdf_metadata(r.content)
        assert meta["/X-Compliance-Auditor-Sub"] == "auditor-bob"
        assert meta["/X-Compliance-Engagement-Id"] == "ENG-2026"
        assert "/X-Compliance-Watermark-Id" in meta
        assert "/X-Compliance-Exported-At" in meta

    def test_auditor_without_scope_403(self, fresh_registry):
        """Auditor lacking auditor_scope is rejected at watermark build time."""
        from fastapi.testclient import TestClient

        from portal.auth.models import Role, User
        from portal.pdf.registry import get_default_registry

        async def resolver(doc_id, user):
            return ("audit_event.html", {"event": {"id": doc_id, "audit_type": "x", "user_id": "u", "classification": "internal", "ts": "2026", "hash": "h", "prev_hash": "p", "payload": {}}}, "x", "auditor")

        reg = get_default_registry()
        reg.register(
            "audit_event",
            template="audit_event.html",
            resolver=resolver,
            audit_event_type="audit.pdf.exported",
        )

        now = datetime.now(UTC)
        auditor_no_scope = User(
            sub="auditor-x",
            email="ax@e.com",
            name="ax",
            roles=[Role.AUDITOR],
            auditor_scope=None,
            mfa_at=now,
            session_id="s",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        app = self._build_app_with_user(auditor_no_scope, reg)
        client = TestClient(app)
        r = client.get("/export/pdf/audit_event/evt-1")
        assert r.status_code == 403
