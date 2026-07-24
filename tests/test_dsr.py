"""WI-08 — Internal DSR Management router tests.

Covers:
  * Queue rendering + SLA band sort
  * Detail page state machine, valid_next_states
  * AMD-01 SoD pre-check (submitter == reviewer → 409 on identity actions)
  * Transition required-field gating
  * Generate-evidence happy path (sync + async)
  * Deliver token (AMD-16 — service authoritative)
  * AMD-12 close invalidates outstanding tokens
  * SLA band boundary correctness
  * RBAC (viewer denied)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from portal.routers import dsr as dsr_router_module
from portal.services.dsr_sla import remaining_days, sla_band

from tests._fakes import build_dsr


# ─── SLA service ──────────────────────────────────────────────────────────────


class TestSlaService:
    def test_remaining_days_30day_window(self):
        submitted = datetime.now(UTC) - timedelta(days=10)
        assert 19.5 < remaining_days(submitted) < 20.5

    def test_band_boundaries(self):
        assert sla_band(31) == "green"
        assert sla_band(8) == "green"
        assert sla_band(7) == "yellow"
        assert sla_band(4) == "yellow"
        assert sla_band(3) == "amber"
        assert sla_band(1.5) == "amber"
        assert sla_band(1) == "red"
        assert sla_band(0.5) == "red"
        assert sla_band(-1) == "overdue"


# ─── Queue ────────────────────────────────────────────────────────────────────


class TestDsrIndex:
    def test_queue_renders(self, build_router_app, make_user, fake_compliance_client):
        d1 = build_dsr(request_id="DSR-1", submitted_days_ago=1, request_type="access")
        d2 = build_dsr(request_id="DSR-2", submitted_days_ago=29, request_type="erasure")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-1"] = d1
        fake_compliance_client.dsr_requests["DSR-2"] = d2
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr")
        assert r.status_code == 200
        assert "DSR-1" in r.text
        assert "DSR-2" in r.text

    def test_queue_sorts_by_sla_urgency(
        self, build_router_app, make_user, fake_compliance_client
    ):
        old = build_dsr(request_id="DSR-OLD", submitted_days_ago=29)  # 1d remaining
        new = build_dsr(request_id="DSR-NEW", submitted_days_ago=1)  # 29d remaining
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-NEW"] = new
        fake_compliance_client.dsr_requests["DSR-OLD"] = old
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr")
        # OLD (more urgent) appears before NEW in body.
        assert r.text.find("DSR-OLD") < r.text.find("DSR-NEW")

    def test_viewer_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr")
        assert r.status_code == 403

    def test_queue_filter_by_request_type(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d1 = build_dsr(request_id="DSR-A", request_type="access")
        d2 = build_dsr(request_id="DSR-E", request_type="erasure")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-A"] = d1
        fake_compliance_client.dsr_requests["DSR-E"] = d2
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr?request_type=erasure")
        assert "DSR-E" in r.text
        assert "DSR-A" not in r.text


# ─── Detail ───────────────────────────────────────────────────────────────────


class TestDsrDetail:
    def test_detail_renders_state_and_next_options(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-D", status="received")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-D"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr/DSR-D")
        assert r.status_code == 200
        assert "received" in r.text
        # received → identity_pending should be in next-options dropdown
        assert "identity_pending" in r.text

    def test_detail_terminal_status_no_transitions(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-CL", status="closed")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-CL"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/dsr/DSR-CL")
        assert r.status_code == 200
        assert "Status terminal" in r.text


# ─── Transitions ──────────────────────────────────────────────────────────────


class TestDsrTransition:
    def test_invalid_transition_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # received → delivered is invalid
        d = build_dsr(request_id="DSR-T", status="received")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-T"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/dsr/DSR-T/transition", data={"to_status": "delivered"})
        assert r.status_code == 400
        assert "invalid transition" in r.text

    def test_verified_requires_verification_method(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-V", status="identity_pending")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-V"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/DSR-V/transition",
                data={"to_status": "verified"},
            )
        assert r.status_code == 400
        assert "verification_method" in r.text

    def test_amd01_sod_blocks_self_verification(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(
            request_id="DSR-SOD",
            status="identity_pending",
            submitted_by="alice-sub",
        )
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-SOD"] = d
        user = make_user(sub="alice-sub", roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/DSR-SOD/transition",
                data={"to_status": "verified", "verification_method": "passport"},
            )
        assert r.status_code == 409
        # Audit recorded
        recorded_types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "dsr.identity_review.sod_blocked" in recorded_types

    def test_valid_transition_succeeds(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-OK", status="received")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-OK"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/dsr/DSR-OK/transition", data={"to_status": "identity_pending"})
        assert r.status_code == 200
        assert fake_compliance_client.dsr_requests["DSR-OK"].status == "identity_pending"


# ─── Evidence generation ─────────────────────────────────────────────────────


class TestDsrEvidence:
    def test_generate_evidence_sync_success(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-EV", status="processing")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-EV"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/dsr/DSR-EV/generate-evidence")
        assert r.status_code == 200
        assert "EVD-DSR-DSR-EV" in r.text

    def test_generate_evidence_invalid_state(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-EV2", status="received")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-EV2"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/dsr/DSR-EV2/generate-evidence")
        assert r.status_code == 400


# ─── Delivery ────────────────────────────────────────────────────────────────


class TestDsrDelivery:
    def test_deliver_in_valid_state(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-DV", status="evidence_generated")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-DV"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/DSR-DV/deliver",
                data={"package_id": "EVD-DSR-DSR-DV", "version": "v1"},
            )
        assert r.status_code == 200
        assert "tok-DSR-DV-0" in fake_compliance_client.dsr_delivery_tokens["DSR-DV"][0].token

    def test_deliver_invalid_state(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-DV2", status="received")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-DV2"] = d
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/DSR-DV2/deliver", data={"package_id": "x", "version": "v1"}
            )
        assert r.status_code == 400


# ─── AMD-12 close invalidates tokens ──────────────────────────────────────────


class TestDsrCloseAmd12:
    def test_close_invalidates_outstanding_tokens(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Set up a delivered DSR with two outstanding tokens.
        d = build_dsr(request_id="DSR-CL2", status="delivered")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-CL2"] = d
        # Issue two tokens by calling deliver (will auto-transition; we'll reset)
        await_ = None  # hack — just seed manually
        from datetime import timedelta as _td
        from shared.api_client import DsrDeliveryToken

        fake_compliance_client.dsr_delivery_tokens["DSR-CL2"] = [
            DsrDeliveryToken(
                request_id="DSR-CL2",
                token="t1",
                expires_at=datetime.now(UTC) + _td(days=7),
                package_id="P",
                version="v1",
            ),
            DsrDeliveryToken(
                request_id="DSR-CL2",
                token="t2",
                expires_at=datetime.now(UTC) + _td(days=7),
                package_id="P",
                version="v1",
            ),
        ]
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/DSR-CL2/close",
                data={"acknowledgment_method": "email"},
            )
        assert r.status_code == 200
        # AMD-12 — all tokens invalidated
        assert fake_compliance_client.dsr_delivery_tokens["DSR-CL2"] == []
        # Audit emission
        recorded_types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "dsr.token.invalidated_on_close" in recorded_types

    def test_close_emits_count_in_audit_payload(
        self, build_router_app, make_user, fake_compliance_client
    ):
        d = build_dsr(request_id="DSR-CL3", status="delivered")
        fake_compliance_client._ensure_dsr_storage()
        fake_compliance_client.dsr_requests["DSR-CL3"] = d
        from datetime import timedelta as _td
        from shared.api_client import DsrDeliveryToken

        fake_compliance_client.dsr_delivery_tokens["DSR-CL3"] = [
            DsrDeliveryToken(
                request_id="DSR-CL3",
                token="x",
                expires_at=datetime.now(UTC) + _td(days=7),
                package_id="P",
                version="v1",
            )
        ]
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dsr_router_module.router, user)
        with TestClient(app) as c:
            r = c.post("/dsr/DSR-CL3/close")
        assert r.status_code == 200
        match = [
            e
            for e in fake_compliance_client.recorded_audit_events
            if e["audit_type"] == "dsr.token.invalidated_on_close"
        ][0]
        assert match["payload"]["token_count"] == 1


# ─── PDF resolver registered ──────────────────────────────────────────────────


class TestDsrPdfRegistration:
    def test_dsr_record_resolver_registered(self):
        # Re-register defensively (fresh_registry fixture in test_pdf_service
        # may have wiped the global between modules).
        from portal.pdf.registry import get_default_registry
        from portal.routers.dsr import register_dsr_pdf_components

        register_dsr_pdf_components()
        reg = get_default_registry()
        assert "dsr_record" in reg
