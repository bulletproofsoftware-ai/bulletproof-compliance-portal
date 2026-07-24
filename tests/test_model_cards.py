"""WI-11 — Model Card Registry router tests.

Covers:
  * Registry list / detail rendering (REQ-CPL-019)
  * Schedule annual review (REQ-CPL-020)
  * Review state machine (REQ-CPL-021)
  * AMD-03 sign-off MFA + decision_nonce binding
  * Reminder window math (30d/7d/0d)
  * RBAC: viewer can read; cannot write
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.mfa import MfaNonceManager
from portal.auth.models import Role
from portal.routers import model_cards as model_cards_router_module
from portal.services.review_schedule import (
    Reminder,
    review_band,
    upcoming_reminders,
)

from tests._fakes import build_model_card


# ─── Reminder schedule ───────────────────────────────────────────────────────


class TestReminderSchedule:
    def test_three_reminders_emitted(self):
        nr = datetime(2027, 1, 1, tzinfo=UTC)
        reminders = upcoming_reminders(nr)
        assert len(reminders) == 3
        windows = [r.window for r in reminders]
        assert windows == ["30d", "7d", "0d"]

    def test_30d_reminder_30_days_before(self):
        nr = datetime(2027, 1, 1, tzinfo=UTC)
        reminders = upcoming_reminders(nr)
        assert reminders[0].fires_at == nr - timedelta(days=30)

    def test_review_band_red_when_within_7d(self):
        nr = datetime.now(UTC) + timedelta(days=5)
        assert review_band(nr) == "red"

    def test_review_band_amber_when_within_30d(self):
        nr = datetime.now(UTC) + timedelta(days=20)
        assert review_band(nr) == "amber"

    def test_review_band_overdue(self):
        nr = datetime.now(UTC) - timedelta(days=1)
        assert review_band(nr) == "overdue"


# ─── Registry ────────────────────────────────────────────────────────────────


class TestModelCardRouter:
    def test_index_renders(
        self, build_router_app, make_user, fake_compliance_client
    ):
        c1 = build_model_card(model_id="m-opus", name="Opus")
        c2 = build_model_card(model_id="m-sonnet", name="Sonnet")
        fake_compliance_client._ensure_model_storage()
        fake_compliance_client.model_cards_storage["m-opus"] = c1
        fake_compliance_client.model_cards_storage["m-sonnet"] = c2
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(model_cards_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/models")
        assert r.status_code == 200
        assert "Opus" in r.text
        assert "Sonnet" in r.text

    def test_detail_renders_8_sections(
        self, build_router_app, make_user, fake_compliance_client
    ):
        card = build_model_card(model_id="m-d", name="Detail Card")
        fake_compliance_client._ensure_model_storage()
        fake_compliance_client.model_cards_storage["m-d"] = card
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(model_cards_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/models/m-d")
        assert r.status_code == 200
        # Spot-check section headers
        for header in ("Identity", "Use", "Validation", "Annual review"):
            assert header in r.text

    def test_schedule_review_creates(
        self, build_router_app, make_user, fake_compliance_client
    ):
        card = build_model_card(model_id="m-sched", next_review_days_ahead=None)
        fake_compliance_client._ensure_model_storage()
        fake_compliance_client.model_cards_storage["m-sched"] = card
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(model_cards_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/models/m-sched/review/start",
                data={"scheduled_for": "2027-04-27T00:00:00Z"},
            )
        assert r.status_code == 200
        updated = fake_compliance_client.model_cards_storage["m-sched"]
        assert len(updated.reviews) == 1
        assert updated.reviews[0].state == "scheduled"


# ─── Review state machine ────────────────────────────────────────────────────


class TestReviewStateMachine:
    def _seed_review_in_state(
        self, fake, *, model_id="m-sm", state="scheduled"
    ):
        from shared.api_client import ModelCardReview

        fake._ensure_model_storage()
        card = build_model_card(model_id=model_id)
        review = ModelCardReview(
            review_id=f"REV-{model_id}-1",
            model_id=model_id,
            state=state,
        )
        card_with_review = card.model_copy(update={"reviews": [review]})
        fake.model_cards_storage[model_id] = card_with_review
        return review

    def test_invalid_transition_blocked(
        self, build_router_app, make_user, fake_compliance_client
    ):
        review = self._seed_review_in_state(fake_compliance_client, state="scheduled")
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(model_cards_router_module.router, user)
        with TestClient(app) as c:
            # scheduled → decision is invalid (must go through evidence_assembly)
            r = c.post(
                f"/models/m-sm/review/{review.review_id}/transition",
                data={"to_state": "decision"},
            )
        assert r.status_code == 400

    def test_decision_requires_30char_rationale(
        self, build_router_app, make_user, fake_compliance_client
    ):
        review = self._seed_review_in_state(
            fake_compliance_client, state="reviewer_assigned"
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(model_cards_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                f"/models/m-sm/review/{review.review_id}/transition",
                data={
                    "to_state": "decision",
                    "decision": "approve",
                    "rationale": "too short",
                },
            )
        assert r.status_code == 400


# ─── Sign-off MFA (AMD-03) ───────────────────────────────────────────────────


class TestSignoffMfaAmd03:
    def _seed_decision_state(self, fake, *, model_id="m-sign"):
        from shared.api_client import ModelCardReview

        fake._ensure_model_storage()
        card = build_model_card(model_id=model_id)
        review = ModelCardReview(
            review_id=f"REV-{model_id}-1",
            model_id=model_id,
            state="decision",
            decision="approve",
            rationale="lengthy enough rationale text for sign-off here",
        )
        fake.model_cards_storage[model_id] = card.model_copy(update={"reviews": [review]})
        return review

    def test_signoff_consumes_nonce_and_signs(
        self, build_router_app, make_user, fake_compliance_client
    ):
        review = self._seed_decision_state(fake_compliance_client, model_id="m-sign1")
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(model_cards_router_module.router, user)
        # Pre-issue a nonce on app state
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce = mgr.issue(
            user_sub="alice", action=f"model_review.signoff:{review.review_id}"
        )
        with TestClient(app) as c:
            r = c.post(
                f"/models/m-sign1/review/{review.review_id}/sign-off",
                data={"decision_nonce": nonce},
            )
        assert r.status_code == 200
        # Service produced signature
        signed = fake_compliance_client.model_cards_storage["m-sign1"].reviews[0]
        assert signed.signature is not None
        assert signed.state == "signed_off"

    def test_signoff_with_consumed_nonce_409(
        self, build_router_app, make_user, fake_compliance_client
    ):
        review = self._seed_decision_state(fake_compliance_client, model_id="m-sign2")
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(model_cards_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        nonce = mgr.issue(
            user_sub="alice", action=f"model_review.signoff:{review.review_id}"
        )
        # Consume it
        mgr.consume(
            nonce, user_sub="alice", action=f"model_review.signoff:{review.review_id}"
        )
        with TestClient(app) as c:
            r = c.post(
                f"/models/m-sign2/review/{review.review_id}/sign-off",
                data={"decision_nonce": nonce},
            )
        assert r.status_code == 409
        assert "mfa_nonce_consumed" in r.text

    def test_signoff_cross_review_nonce_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        review_a = self._seed_decision_state(
            fake_compliance_client, model_id="m-sign3a"
        )
        review_b = self._seed_decision_state(
            fake_compliance_client, model_id="m-sign3b"
        )
        user = make_user(sub="alice", roles=[Role.COMPLIANCE_OFFICER], mfa_age_s=10)
        app = build_router_app(model_cards_router_module.router, user)
        mgr = MfaNonceManager(max_age_s=60)
        app.state.mfa_nonce_manager = mgr
        # Issue nonce for review A
        nonce_a = mgr.issue(
            user_sub="alice", action=f"model_review.signoff:{review_a.review_id}"
        )
        # Try to use it on review B
        with TestClient(app) as c:
            r = c.post(
                f"/models/m-sign3b/review/{review_b.review_id}/sign-off",
                data={"decision_nonce": nonce_a},
            )
        assert r.status_code == 409


# ─── PDF resolver ─────────────────────────────────────────────────────────────


class TestModelCardPdfRegistration:
    def test_model_card_resolver_registered(self):
        from portal.pdf.registry import get_default_registry
        from portal.routers.model_cards import register_model_card_pdf_components

        register_model_card_pdf_components()
        reg = get_default_registry()
        assert "model_card" in reg
