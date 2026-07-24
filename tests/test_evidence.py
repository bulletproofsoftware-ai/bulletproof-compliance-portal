"""WI-05 — Evidence Package Library router tests (REQ-CPL-007, REQ-CPL-008).

Covers:
  * GET /evidence list page with signature status
  * GET /evidence/{id} detail page (signature panel)
  * GET /evidence/{id}/versions partial
  * GET /evidence/{id}/diff?from=v1&to=v2 partial
  * GET /evidence/{id}/verify Ed25519 verification banner
  * GET /evidence/{id}/download triggers audit log entry (REQ-CPL-007 — user, IP,
    purpose, package_id)
  * AMD-06: auditor download → redirect to /export/pdf/evidence_package/{id}
    so the watermark + identity metadata are applied by the export router
  * Non-auditor download → audit event WITHOUT watermarked=True flag
  * RBAC: viewer cannot access evidence routes
  * PDF resolver "evidence_package" registered with allowed roles
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import AuditorScope, Role
from portal.routers import evidence as evidence_router_module
from shared.api_client import (
    EvidenceDiff,
    EvidenceSignatureStatus,
    EvidenceVersion,
)

from tests._fakes import build_evidence_package


def _auditor_user(make_user, *, allowed_artifact_types: list[str] | None = None):
    now = datetime.now(UTC)
    scope = AuditorScope(
        engagement_id="ENG-EV-1",
        engagement_start=now - timedelta(days=1),
        engagement_end=now + timedelta(days=30),
        date_range_start=now - timedelta(days=365),
        date_range_end=now,
        allowed_artifact_types=allowed_artifact_types
        or ["audit_event", "evidence_package", "gate_decision"],
        allowed_project_ids=None,
    )
    return make_user(
        sub="auditor-ev-1",
        roles=[Role.AUDITOR],
        auditor_scope=scope,
    )


# ─── Index ────────────────────────────────────────────────────────────────────


class TestEvidenceIndex:
    def test_returns_200_with_package_list(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-001", title="SOC2 Q1")
        )
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-002", title="ISO27001 audit")
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence")
        assert r.status_code == 200
        assert "EV-001" in r.text
        assert "EV-002" in r.text
        assert "SOC2 Q1" in r.text

    def test_empty_list_renders_no_packages_msg(
        self, build_router_app, make_user
    ):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence")
        assert r.status_code == 200
        assert "No evidence packages" in r.text

    def test_viewer_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence")
        assert r.status_code == 403


# ─── Detail page ──────────────────────────────────────────────────────────────


class TestEvidenceDetail:
    def test_detail_includes_signature_status(
        self, build_router_app, make_user, fake_compliance_client
    ):
        pkg = build_evidence_package(package_id="EV-100", title="Q4 evidence")
        fake_compliance_client.evidence_packages.append(pkg)
        # Seed a VALID signature
        fake_compliance_client.evidence_signatures["EV-100"] = EvidenceSignatureStatus(
            package_id="EV-100",
            version="v1",
            valid=True,
            algorithm="Ed25519",
            signing_key_id="key-2026-q1",
            signed_at=datetime.now(UTC),
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-100")
        assert r.status_code == 200
        assert "EV-100" in r.text
        assert "VALID" in r.text
        assert "Ed25519" in r.text


# ─── Versions partial ─────────────────────────────────────────────────────────


class TestEvidenceVersions:
    def test_versions_partial_renders_history(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-VER", title="Versioned")
        )
        now = datetime.now(UTC)
        fake_compliance_client.evidence_versions["EV-VER"] = [
            EvidenceVersion(
                package_id="EV-VER",
                version="v1",
                created_at=now - timedelta(days=2),
                created_by="alice",
                note="initial",
                artifact_hash="h-v1",
            ),
            EvidenceVersion(
                package_id="EV-VER",
                version="v2",
                created_at=now,
                created_by="bob",
                note="revised",
                artifact_hash="h-v2",
            ),
        ]
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-VER/versions")
        assert r.status_code == 200
        assert "v1" in r.text
        assert "v2" in r.text
        assert "alice" in r.text
        assert "h-v2" in r.text
        # Should NOT contain a full HTML root — partial fragment
        assert "<html" not in r.text.lower()


# ─── Diff partial ─────────────────────────────────────────────────────────────


class TestEvidenceDiff:
    def test_diff_partial_renders_unified_diff(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-DIFF")
        )
        fake_compliance_client.evidence_diffs[("EV-DIFF", "v1", "v2")] = EvidenceDiff(
            package_id="EV-DIFF",
            from_version="v1",
            to_version="v2",
            diff_text="@@ -1 +1 @@\n-old line\n+new line\n",
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-DIFF/diff", params={"from": "v1", "to": "v2"})
        assert r.status_code == 200
        # Diff text appears verbatim (Jinja autoescape preserves content)
        assert "old line" in r.text
        assert "new line" in r.text
        assert "v1" in r.text
        assert "v2" in r.text

    def test_diff_requires_from_param(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-X/diff", params={"to": "v2"})
        assert r.status_code == 422  # FastAPI validation error


# ─── Verify partial ───────────────────────────────────────────────────────────


class TestEvidenceVerify:
    def test_verify_returns_valid_banner(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_signatures["EV-V"] = EvidenceSignatureStatus(
            package_id="EV-V",
            version="v1",
            valid=True,
            algorithm="Ed25519",
            signing_key_id="key-1",
            signed_at=datetime.now(UTC),
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-V/verify")
        assert r.status_code == 200
        assert "VALID" in r.text
        assert "Ed25519" in r.text

    def test_verify_returns_invalid_banner(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_signatures["EV-X"] = EvidenceSignatureStatus(
            package_id="EV-X",
            version="v1",
            valid=False,
            algorithm="Ed25519",
            signing_key_id="key-1",
            signed_at=datetime.now(UTC),
            note="signature mismatch",
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-X/verify")
        assert r.status_code == 200
        assert "INVALID" in r.text


# ─── Download — audit logging (REQ-CPL-007) ──────────────────────────────────


class TestEvidenceDownload:
    def test_non_auditor_download_records_audit_event(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-DL")
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get(
                "/evidence/EV-DL/download",
                params={"purpose": "quarterly review"},
                follow_redirects=False,
            )
        # Either a redirect to download_url or a JSON response
        assert r.status_code in {200, 303}
        recorded = fake_compliance_client.recorded_audit_events
        assert any(
            e["audit_type"] == "evidence.download.initiated" for e in recorded
        ), f"expected evidence.download.initiated in {[e['audit_type'] for e in recorded]}"
        # The audit event must contain user, IP, purpose, package_id
        evt = next(
            e for e in recorded if e["audit_type"] == "evidence.download.initiated"
        )
        assert evt["user_id"] == "alice"
        assert evt["payload"]["package_id"] == "EV-DL"
        assert evt["payload"]["purpose"] == "quarterly review"
        assert "ip" in evt["payload"]
        # Non-auditor users — watermarked is FALSE
        assert evt["payload"]["watermarked"] is False

    def test_auditor_download_redirects_to_pdf_export(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """AMD-06 — auditor downloads MUST be watermarked → routed through
        /export/pdf/evidence_package/{id} which applies the watermark."""
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-WM")
        )
        user = _auditor_user(make_user)
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-WM/download", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/export/pdf/evidence_package/EV-WM"

    def test_auditor_download_audit_event_marks_watermarked(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.evidence_packages.append(
            build_evidence_package(package_id="EV-WM2")
        )
        user = _auditor_user(make_user)
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            client.get("/evidence/EV-WM2/download", follow_redirects=False)
        evt = next(
            e
            for e in fake_compliance_client.recorded_audit_events
            if e["audit_type"] == "evidence.download.initiated"
        )
        # Watermarked True for auditor — auditor identity will be applied by
        # the PDF export router downstream.
        assert evt["payload"]["watermarked"] is True

    def test_viewer_forbidden_from_download(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(evidence_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/evidence/EV-DL/download")
        assert r.status_code == 403


# ─── PDF resolver registration ────────────────────────────────────────────────


class TestEvidencePdfResolver:
    def test_evidence_package_resolver_registered(self):
        from portal.pdf.registry import get_default_registry

        evidence_router_module.register_evidence_pdf_components()
        reg = get_default_registry()
        assert "evidence_package" in reg
        spec = reg.get("evidence_package")
        assert spec is not None
        assert spec.audit_event_type == "evidence.pdf.exported"
        assert "auditor" in spec.allowed_roles
        assert "compliance_officer" in spec.allowed_roles
