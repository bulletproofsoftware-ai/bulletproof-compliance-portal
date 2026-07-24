"""WI-12 — Regulatory Report Generation router tests.

Covers:
  * 4 report-type forms render
  * Stage state machine (draft → review → approved → signed → delivered)
  * SoD: review→approved blocks creator
  * AMD-03 sign requires MFA + nonce; nonce binding to specific report_id
  * Service authoritative for signing (portal does NOT compute signature)
  * Delivery records + advance to delivered
  * Auditor / viewer cannot transition (RBAC)
  * AMD-08 byterange signature wired through PDF resolver
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from portal.auth.mfa import MfaNonceManager
from portal.auth.models import Role
from portal.routers import reports as reports_router_module
from portal.services.report_workflow import (
    is_valid_transition,
    valid_next_stages,
    can_sign,
    can_deliver,
)

from tests._fakes import build_report


# ─── State machine pure functions ────────────────────────────────────────────


class TestReportWorkflow:
    def test_valid_transitions(self):
        assert is_valid_transition("draft", "review")
        assert is_valid_transition("review", "approved")
        assert is_valid_transition("approved", "signed")
        assert is_valid_transition("signed", "delivered")

    def test_invalid_transitions(self):
        assert not is_valid_transition("draft", "signed")
        assert not is_valid_transition("draft", "approved")
        assert not is_valid_transition("approved", "draft")
        assert not is_valid_transition("signed", "approved")  # immutable
        assert not is_valid_transition("delivered", "approved")

    def test_can_sign_only_in_approved(self):
        assert can_sign("approved")
        assert not can_sign("draft")
        assert not can_sign("signed")

    def test_can_deliver_only_in_signed(self):
        assert can_deliver("signed")
        assert not can_deliver("approved")

    def test_valid_next_stages_signed(self):
        assert valid_next_stages("signed") == ["delivered"]

    def test_valid_next_stages_delivered_terminal(self):
        assert valid_next_stages("delivered") == []


# ─── Form rendering ──────────────────────────────────────────────────────────


class TestReportForms:
    def test_sox_form_renders(self, build_router_app, make_user, fake_compliance_client):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports/new/sox_attestation")
        assert r.status_code == 200
        assert "SOX" in r.text

    def test_nydfs_form_renders(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports/new/nydfs_part500")
        assert r.status_code == 200
        assert "NY DFS" in r.text

    def test_eu_ai_act_form_renders(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports/new/eu_ai_act_conformity")
        assert r.status_code == 200
        assert "EU AI Act" in r.text

    def test_naic_form_renders(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports/new/naic_adverse_action")
        assert r.status_code == 200
        assert "NAIC" in r.text

    def test_unknown_type_404(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports/new/bogus_type")
        assert r.status_code == 404


# ─── Generation ──────────────────────────────────────────────────────────────


class TestReportGenerate:
    def test_sox_generation(self, build_router_app, make_user, fake_compliance_client):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/generate",
                data={
                    "report_type": "sox_attestation",
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-12-31T23:59:59Z",
                    "scope_notes": "Q4 controls",
                },
            )
        assert r.status_code == 200
        assert len(fake_compliance_client.reports_storage) == 1
        rid = next(iter(fake_compliance_client.reports_storage))
        assert fake_compliance_client.reports_storage[rid].report_type == "sox_attestation"

    def test_eu_ai_act_requires_high_risk_change_id(
        self, build_router_app, make_user, fake_compliance_client
    ):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/generate",
                data={"report_type": "eu_ai_act_conformity"},
            )
        assert r.status_code == 400


# ─── Transitions + SoD ───────────────────────────────────────────────────────


class TestReportTransitions:
    def test_draft_to_review(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-1", stage="draft", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-1"] = rpt
        user = make_user(sub="bob", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/reports/R-1/review")
        assert r.status_code == 200
        assert fake_compliance_client.reports_storage["R-1"].stage == "review"

    def test_review_to_approved_blocks_creator_sod(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-2", stage="review", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-2"] = rpt
        user = make_user(sub="alice", roles=[Role.ADMIN])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/reports/R-2/approve")
        assert r.status_code == 403
        # Audit emission
        recorded = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "report.approve.sod_blocked" in recorded

    def test_review_to_approved_admin_only(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-3", stage="review", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-3"] = rpt
        user = make_user(sub="bob", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/reports/R-3/approve")
        # compliance_officer (not admin) cannot approve
        assert r.status_code == 403

    def test_approve_advances_when_admin_and_not_creator(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-4", stage="review", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-4"] = rpt
        user = make_user(sub="admin-1", roles=[Role.ADMIN])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/reports/R-4/approve")
        assert r.status_code == 200
        assert fake_compliance_client.reports_storage["R-4"].stage == "approved"


# ─── AMD-03 Sign action MFA + nonce ───────────────────────────────────────────


class TestReportSignAmd03:
    def test_sign_succeeds_with_valid_nonce(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-S1", stage="approved", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-S1"] = rpt
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(reports_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce = mgr.issue(user_sub="alice", action="report.sign:R-S1")
        with TestClient(app) as c:
            r = c.post("/reports/R-S1/sign", data={"decision_nonce": nonce})
        assert r.status_code == 200
        # Service produced signature; portal NEVER computed it
        signed = fake_compliance_client.reports_storage["R-S1"]
        assert signed.signature is not None
        assert signed.signing_key_id == "key-2026-q1"
        assert signed.stage == "signed"

    def test_sign_in_wrong_stage_400(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-S2", stage="draft", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-S2"] = rpt
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(reports_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce = mgr.issue(user_sub="alice", action="report.sign:R-S2")
        with TestClient(app) as c:
            r = c.post("/reports/R-S2/sign", data={"decision_nonce": nonce})
        assert r.status_code == 400

    def test_sign_with_cross_report_nonce_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt_a = build_report(report_id="R-A", stage="approved", created_by="alice")
        rpt_b = build_report(report_id="R-B", stage="approved", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-A"] = rpt_a
        fake_compliance_client.reports_storage["R-B"] = rpt_b
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(reports_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce_a = mgr.issue(user_sub="alice", action="report.sign:R-A")
        with TestClient(app) as c:
            r = c.post("/reports/R-B/sign", data={"decision_nonce": nonce_a})
        assert r.status_code == 409
        assert "mfa_nonce_consumed" in r.text

    def test_sign_with_consumed_nonce_409(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-S3", stage="approved", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-S3"] = rpt
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(reports_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce = mgr.issue(user_sub="alice", action="report.sign:R-S3")
        # Consume it externally
        mgr.consume(nonce, user_sub="alice", action="report.sign:R-S3")
        with TestClient(app) as c:
            r = c.post("/reports/R-S3/sign", data={"decision_nonce": nonce})
        assert r.status_code == 409


# ─── Delivery ────────────────────────────────────────────────────────────────


class TestReportDeliver:
    def test_deliver_records_and_advances(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-D", stage="signed", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-D"] = rpt
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/R-D/deliver",
                data={
                    "recipient": "regulator@ny.gov",
                    "channel": "email",
                    "confirmation_receipt": "RR-001",
                },
            )
        assert r.status_code == 200
        rec = fake_compliance_client.reports_storage["R-D"]
        assert len(rec.deliveries) == 1
        assert rec.deliveries[0].confirmation_receipt == "RR-001"
        assert rec.stage == "delivered"

    def test_deliver_invalid_channel_400(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-DC", stage="signed", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-DC"] = rpt
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/R-DC/deliver",
                data={"recipient": "x", "channel": "carrier_pigeon"},
            )
        assert r.status_code == 400

    def test_deliver_in_wrong_stage_400(
        self, build_router_app, make_user, fake_compliance_client
    ):
        rpt = build_report(report_id="R-DW", stage="draft", created_by="alice")
        fake_compliance_client._ensure_reports_storage()
        fake_compliance_client.reports_storage["R-DW"] = rpt
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/R-DW/deliver",
                data={"recipient": "x", "channel": "email"},
            )
        assert r.status_code == 400


# ─── PDF resolver + AMD-08 wiring ─────────────────────────────────────────────


class TestReportsPdfRegistration:
    @pytest.fixture(autouse=True)
    def _ensure_registered(self):
        from portal.routers.reports import register_report_pdf_components
        register_report_pdf_components()

    def test_regulatory_report_resolver_registered(self):
        from portal.pdf.registry import get_default_registry

        reg = get_default_registry()
        assert "regulatory_report" in reg

    def test_amd08_pades_required_for_signed(self):
        from portal.pdf.registry import get_default_registry

        spec = get_default_registry().get("regulatory_report")
        assert spec is not None
        # PAdES requirement
        ctx = {"report": {"stage": "signed", "signature": "abcd"}}
        assert spec.requires_pades(ctx) is True
        ctx_unsigned = {"report": {"stage": "draft"}}
        assert spec.requires_pades(ctx_unsigned) is False

    def test_signature_extracted_for_signed_report(self):
        from portal.pdf.registry import get_default_registry

        spec = get_default_registry().get("regulatory_report")
        assert spec is not None
        ctx = {
            "report": {
                "stage": "signed",
                "signature": "ZmFrZS1zaWduYXR1cmU=",
                "signing_key_id": "key-2026-q1",
                "signed_at": "2026-04-27T00:00:00Z",
                "signed_by": "alice",
            }
        }
        sig = spec.extract_signature(ctx)
        assert sig is not None
        assert sig.signing_key_id == "key-2026-q1"
        assert sig.signature.startswith("ZmFrZS1z")


# ─── Viewer / Auditor RBAC ────────────────────────────────────────────────────


class TestRbac:
    def test_viewer_can_read_list(
        self, build_router_app, make_user, fake_compliance_client
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/reports")
        assert r.status_code == 200

    def test_viewer_cannot_generate(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(reports_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/reports/generate",
                data={
                    "report_type": "sox_attestation",
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-12-31T00:00:00Z",
                },
            )
        assert r.status_code == 403
