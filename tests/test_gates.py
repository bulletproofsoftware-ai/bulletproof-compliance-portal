"""WI-06 — Gate Decision Workspace router tests (REQ-CPL-009/010/011, AMD-03/14).

Covers:
  * Pending queue rendering (sorted upstream — portal just displays)
  * Decision-form view (evidence panel, MFA-required indicator)
  * Decision submission (approve / deny / escalate)
  * AMD-03: confidential/restricted require fresh MFA + decision_nonce
  * AMD-03: nonce binding to specific gate_id (cross-gate replay rejected)
  * AMD-03: nonce expiry (>60s rejected)
  * REQ-CPL-010 (SOX SoD): triggered_by == current_user.sub → 403
  * Decision submission generates signed receipt via ComplianceClient
  * GET /gates/{id}/receipt re-fetches receipt
  * AMD-14 trust boundary: portal does NOT modify triggered_by on requests
  * RBAC: only compliance_officer / admin can submit decisions
  * HTMX patterns
  * Mandatory rationale (min length 20)
  * Internal classification works without MFA / nonce
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.mfa import MfaNonceManager
from portal.auth.models import Role
from portal.routers import gates as gates_router_module

from tests._fakes import build_evidence_package, build_human_gate


def _seed_mfa_nonce(app, *, user_sub: str, gate_id: str) -> str:
    """Pre-issue an MFA decision nonce on the app's nonce manager and return it."""
    mgr = MfaNonceManager(max_age_s=60)
    app.state.mfa_nonce_manager = mgr
    return mgr.issue(user_sub=user_sub, action=f"gate.decide:{gate_id}")


# ─── Pending queue ────────────────────────────────────────────────────────────


class TestGatesIndex:
    def test_returns_pending_queue(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Seed two gates with different SLAs
        now = datetime.now(UTC)
        g1 = build_human_gate(
            gate_id="G-1",
            title="Approve dataset publication",
            classification="confidential",
            sla_in_seconds=1800,  # 30 min — RED band
        )
        g2 = build_human_gate(
            gate_id="G-2",
            title="Routine internal review",
            classification="internal",
            sla_in_seconds=24 * 3600,  # 24h — GREEN band
        )
        fake_compliance_client.gates["G-1"] = g1
        fake_compliance_client.gates["G-2"] = g2
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates")
        assert r.status_code == 200
        assert "G-1" in r.text
        assert "G-2" in r.text
        assert "Approve dataset publication" in r.text

    def test_empty_queue(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates")
        assert r.status_code == 200
        assert "No pending gates" in r.text

    def test_viewer_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates")
        assert r.status_code == 403

    def test_auditor_forbidden_from_decision_workspace(
        self, build_router_app, make_user
    ):
        # Auditor is read-only and should not be on the decision workspace.
        user = make_user(roles=[Role.AUDITOR])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates")
        assert r.status_code == 403


# ─── Detail view ──────────────────────────────────────────────────────────────


class TestGateDetail:
    def test_detail_renders_form_and_evidence_panel(
        self, build_router_app, make_user, fake_compliance_client
    ):
        gate = build_human_gate(
            gate_id="GD-1",
            title="Approve dataset",
            classification="confidential",
            triggered_by="bob",
            evidence_package_ids=["EV-1", "EV-2"],
        )
        fake_compliance_client.gates["GD-1"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates/GD-1")
        assert r.status_code == 200
        assert "Approve dataset" in r.text
        assert "EV-1" in r.text
        assert "EV-2" in r.text
        # Decision form fields
        assert 'name="decision"' in r.text
        assert 'name="rationale"' in r.text
        # Confidential → MFA prompt
        assert "MFA step-up" in r.text
        # Decision nonce embedded as hidden input
        assert 'name="decision_nonce"' in r.text

    def test_internal_classification_no_mfa_step_up_message(
        self, build_router_app, make_user, fake_compliance_client
    ):
        gate = build_human_gate(
            gate_id="GD-INT",
            title="Internal gate",
            classification="internal",
            triggered_by="bob",
        )
        fake_compliance_client.gates["GD-INT"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates/GD-INT")
        assert r.status_code == 200
        # No MFA step-up message and no decision_nonce hidden input
        assert "MFA step-up" not in r.text
        # The hidden nonce input should not be rendered when not required
        assert 'name="decision_nonce"' not in r.text

    def test_sod_violation_disables_form(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # triggered_by == current_user.sub → SoD violation, form disabled
        gate = build_human_gate(
            gate_id="GD-SOD",
            title="Self-triggered",
            classification="confidential",
            triggered_by="alice",
        )
        fake_compliance_client.gates["GD-SOD"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/gates/GD-SOD")
        assert r.status_code == 200
        # Form disabled → SoD warning visible
        assert "separation of duties" in r.text.lower()
        # Submit button is disabled
        assert "disabled" in r.text


# ─── Decision submission ──────────────────────────────────────────────────────


class TestGateDecide:
    def test_internal_decision_works_without_nonce(
        self, build_router_app, make_user, fake_compliance_client
    ):
        gate = build_human_gate(
            gate_id="DEC-INT",
            classification="internal",
            triggered_by="bob",
        )
        fake_compliance_client.gates["DEC-INT"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/DEC-INT/decide",
                data={
                    "decision": "approve",
                    "rationale": "evidence reviewed and approved by compliance team",
                },
            )
        assert r.status_code == 200
        # decide_human_gate was called once
        assert len(fake_compliance_client.decide_calls) == 1
        call = fake_compliance_client.decide_calls[0]
        assert call["gate_id"] == "DEC-INT"
        assert call["decision"] == "approve"
        assert "evidence reviewed" in call["rationale"]
        # Receipt rendered
        assert "rcpt-DEC-INT" in r.text

    def test_confidential_decision_without_nonce_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        gate = build_human_gate(
            gate_id="DEC-CONF",
            classification="confidential",
            triggered_by="bob",
        )
        fake_compliance_client.gates["DEC-CONF"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/DEC-CONF/decide",
                data={
                    "decision": "approve",
                    "rationale": "this rationale is at least twenty characters long",
                    # decision_nonce intentionally missing
                },
            )
        # Missing nonce → 400 (router enforces nonce-required for this class)
        assert r.status_code in {400, 403}
        assert len(fake_compliance_client.decide_calls) == 0

    def test_confidential_decision_with_valid_nonce_succeeds(
        self, build_router_app, make_user, fake_compliance_client
    ):
        gate = build_human_gate(
            gate_id="DEC-CONF2",
            classification="confidential",
            triggered_by="bob",
        )
        fake_compliance_client.gates["DEC-CONF2"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        nonce = _seed_mfa_nonce(app, user_sub="alice", gate_id="DEC-CONF2")
        with TestClient(app) as client:
            r = client.post(
                "/gates/DEC-CONF2/decide",
                data={
                    "decision": "deny",
                    "rationale": "policy violation discovered during review",
                    "decision_nonce": nonce,
                },
            )
        assert r.status_code == 200
        assert len(fake_compliance_client.decide_calls) == 1
        call = fake_compliance_client.decide_calls[0]
        assert call["decision"] == "deny"
        assert call["decision_nonce"] == nonce

    def test_nonce_for_other_gate_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """AMD-03 — nonce is bound to specific (user, gate). Cross-gate use rejected."""
        # Two confidential gates, both not self-triggered
        for gid in ("GA", "GB"):
            fake_compliance_client.gates[gid] = build_human_gate(
                gate_id=gid, classification="confidential", triggered_by="bob"
            )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        # Nonce bound to GA
        nonce_for_ga = _seed_mfa_nonce(app, user_sub="alice", gate_id="GA")
        with TestClient(app) as client:
            # Submit it against GB
            r = client.post(
                "/gates/GB/decide",
                data={
                    "decision": "approve",
                    "rationale": "valid 20-char rationale text here",
                    "decision_nonce": nonce_for_ga,
                },
            )
        assert r.status_code == 403
        assert len(fake_compliance_client.decide_calls) == 0

    def test_expired_nonce_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """AMD-03 — nonce TTL is 60s. Expired nonces must be rejected."""
        fake_compliance_client.gates["DEC-EXP"] = build_human_gate(
            gate_id="DEC-EXP", classification="confidential", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        # Use a nonce manager with max_age_s=0 so any token is immediately expired
        mgr = MfaNonceManager(max_age_s=0)
        app.state.mfa_nonce_manager = mgr
        token = mgr.issue("alice", "gate.decide:DEC-EXP")
        time.sleep(0.01)
        with TestClient(app) as client:
            r = client.post(
                "/gates/DEC-EXP/decide",
                data={
                    "decision": "approve",
                    "rationale": "valid 20-char rationale text here",
                    "decision_nonce": token,
                },
            )
        assert r.status_code == 403
        assert len(fake_compliance_client.decide_calls) == 0

    def test_sod_violation_returns_403(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """REQ-CPL-010 — SOX SoD. The same identity that fired the gate cannot decide it."""
        gate = build_human_gate(
            gate_id="SOD-A",
            classification="internal",  # avoid MFA path; isolate to SoD
            triggered_by="alice",
        )
        fake_compliance_client.gates["SOD-A"] = gate
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/SOD-A/decide",
                data={
                    "decision": "approve",
                    "rationale": "this should never be accepted by the route",
                },
            )
        assert r.status_code == 403
        assert "separation of duties" in r.text.lower()
        # SoD audit event recorded
        types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "gate.decision.sod_blocked" in types
        # decide_human_gate NEVER reached
        assert len(fake_compliance_client.decide_calls) == 0

    def test_invalid_decision_value_400(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.gates["GX"] = build_human_gate(
            gate_id="GX", classification="internal", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/GX/decide",
                data={
                    "decision": "approveeeee",  # invalid
                    "rationale": "valid rationale text twenty plus chars",
                },
            )
        assert r.status_code == 400

    def test_empty_rationale_rejected_422(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """Mandatory rationale — FastAPI validation rejects min_length<20."""
        fake_compliance_client.gates["GR"] = build_human_gate(
            gate_id="GR", classification="internal", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/GR/decide",
                data={"decision": "approve", "rationale": "too short"},
            )
        # FastAPI Form min_length validation → 422
        assert r.status_code == 422

    def test_escalate_requires_target_role(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.gates["GE"] = build_human_gate(
            gate_id="GE", classification="internal", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/GE/decide",
                data={
                    "decision": "escalate",
                    "rationale": "valid rationale text twenty plus chars",
                    # no escalate_to_role
                },
            )
        assert r.status_code == 400

    def test_escalate_passes_target_role_to_client(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.gates["GE2"] = build_human_gate(
            gate_id="GE2", classification="internal", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/GE2/decide",
                data={
                    "decision": "escalate",
                    "rationale": "needs admin signoff per policy",
                    "escalate_to_role": "admin",
                },
            )
        assert r.status_code == 200
        call = fake_compliance_client.decide_calls[0]
        assert call["decision"] == "escalate"
        assert call["escalate_to_role"] == "admin"


# ─── Receipt re-fetch ─────────────────────────────────────────────────────────


class TestGateReceipt:
    def test_receipt_route_returns_signed_receipt(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Decide first to seed a receipt
        fake_compliance_client.gates["RCT-1"] = build_human_gate(
            gate_id="RCT-1", classification="internal", triggered_by="bob"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            client.post(
                "/gates/RCT-1/decide",
                data={
                    "decision": "approve",
                    "rationale": "approved per compliance review minutes",
                },
            )
            r = client.get("/gates/RCT-1/receipt")
        assert r.status_code == 200
        assert "rcpt-RCT-1" in r.text
        assert "Decision recorded and signed" in r.text


# ─── AMD-14 trust boundary ────────────────────────────────────────────────────


class TestTriggeredByTrustBoundary:
    def test_portal_does_not_modify_triggered_by(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """AMD-14 — the portal MUST NOT have any code path that lets the portal
        SET triggered_by on a gate. Since `decide_human_gate` is the only
        write call, verify it was called with NO triggered_by override.
        """
        fake_compliance_client.gates["TB-1"] = build_human_gate(
            gate_id="TB-1",
            classification="internal",
            triggered_by="upstream-agent-id",
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(gates_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/gates/TB-1/decide",
                data={
                    "decision": "approve",
                    "rationale": "verified evidence is authentic",
                },
            )
        assert r.status_code == 200
        call = fake_compliance_client.decide_calls[0]
        # The portal's decide call has no `triggered_by` parameter at all
        assert "triggered_by" not in call
        # Underlying gate's triggered_by remained untouched in fake state
        assert (
            fake_compliance_client.gates["TB-1"].triggered_by == "upstream-agent-id"
        )


# ─── PDF resolver registration ────────────────────────────────────────────────


class TestGatePdfResolver:
    def test_gate_decision_resolver_registered(self):
        from portal.pdf.registry import get_default_registry

        gates_router_module.register_gate_pdf_components()
        reg = get_default_registry()
        assert "gate_decision" in reg
        spec = reg.get("gate_decision")
        assert spec is not None
        assert spec.audit_event_type == "gate.decision.pdf.exported"
