"""WI-07 — Auditor Access Controls tests (REQ-CPL-033, 034, 035).

Covers two surfaces:

  1. Admin engagement management (`/admin/auditor-engagements`)
     - Create / list / detail / revoke (admin only)
     - Validation: end > start, no_renewal default
     - Non-admin attempts → 403

  2. Auditor scope enforcement (`portal.auth.auditor_scope`)
     - `require_active_engagement` rejects expired / revoked / missing
     - `enforce_artifact_scope` rejects out-of-scope artifact_type
     - `log_artifact_view` writes to access log (REQ-CPL-034)
     - Non-auditor users pass through

  3. AMD-09: every auditor artifact view is logged with engagement_id +
     artifact_type + artifact_id
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from portal.auth.auditor_scope import (
    EngagementInactive,
    enforce_artifact_scope,
    log_artifact_view,
    require_active_engagement,
)
from portal.auth.models import AuditorScope, Role
from portal.routers import auditor_admin as auditor_admin_router_module

from tests._fakes import build_engagement


def _auditor_user(make_user, *, engagement_end_days: int = 30, allowed: list[str] | None = None):
    now = datetime.now(UTC)
    scope = AuditorScope(
        engagement_id="ENG-AUD-1",
        engagement_start=now - timedelta(days=1),
        engagement_end=now + timedelta(days=engagement_end_days),
        date_range_start=now - timedelta(days=365),
        date_range_end=now,
        allowed_artifact_types=allowed
        or ["audit_event", "evidence_package", "gate_decision"],
        allowed_project_ids=None,
    )
    return make_user(
        sub="aud-1", roles=[Role.AUDITOR], auditor_scope=scope, mfa_age_s=10
    )


# ─── Admin engagement management ──────────────────────────────────────────────


class TestEngagementsAdminIndex:
    def test_admin_can_list(self, build_router_app, make_user, fake_compliance_client):
        fake_compliance_client.engagements["ENG-1"] = build_engagement(
            engagement_id="ENG-1"
        )
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/admin/auditor-engagements")
        assert r.status_code == 200
        assert "ENG-1" in r.text
        # Create form is on the index page
        assert 'name="auditor_email"' in r.text

    def test_non_admin_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/admin/auditor-engagements")
        assert r.status_code == 403

    def test_auditor_cannot_access_admin(self, build_router_app, make_user):
        user = _auditor_user(make_user)
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/admin/auditor-engagements")
        assert r.status_code == 403


class TestEngagementsAdminCreate:
    def test_admin_creates_engagement(
        self, build_router_app, make_user, fake_compliance_client
    ):
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        now = datetime.now(UTC)
        with TestClient(app) as client:
            r = client.post(
                "/admin/auditor-engagements",
                data={
                    "auditor_email": "auditor@firm.example",
                    "engagement_start": (now - timedelta(days=1)).isoformat(),
                    "engagement_end": (now + timedelta(days=30)).isoformat(),
                    "date_range_start": (now - timedelta(days=365)).isoformat(),
                    "date_range_end": now.isoformat(),
                    "allowed_artifact_types": "audit_event,evidence_package",
                    "allowed_project_ids": "proj-A,proj-B",
                },
                follow_redirects=False,
            )
        assert r.status_code == 303
        assert "/admin/auditor-engagements/" in r.headers["location"]
        # Engagement created on the fake client
        assert len(fake_compliance_client.create_engagement_calls) == 1
        assert (
            fake_compliance_client.create_engagement_calls[0]["auditor_email"]
            == "auditor@firm.example"
        )

    def test_engagement_end_must_be_after_start(
        self, build_router_app, make_user
    ):
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        now = datetime.now(UTC)
        with TestClient(app) as client:
            r = client.post(
                "/admin/auditor-engagements",
                data={
                    "auditor_email": "x@y",
                    "engagement_start": (now + timedelta(days=10)).isoformat(),
                    "engagement_end": now.isoformat(),  # before start
                    "date_range_start": (now - timedelta(days=10)).isoformat(),
                    "date_range_end": now.isoformat(),
                },
            )
        assert r.status_code == 400

    def test_non_admin_cannot_create(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(auditor_admin_router_module.router, user)
        now = datetime.now(UTC)
        with TestClient(app) as client:
            r = client.post(
                "/admin/auditor-engagements",
                data={
                    "auditor_email": "x@y",
                    "engagement_start": now.isoformat(),
                    "engagement_end": (now + timedelta(days=10)).isoformat(),
                    "date_range_start": (now - timedelta(days=10)).isoformat(),
                    "date_range_end": now.isoformat(),
                },
            )
        assert r.status_code == 403


class TestEngagementsAdminDetail:
    def test_admin_sees_detail_with_access_log(
        self, build_router_app, make_user, fake_compliance_client
    ):
        from shared.api_client import EngagementAccessLogEntry

        eng = build_engagement(engagement_id="ENG-D")
        fake_compliance_client.engagements["ENG-D"] = eng
        fake_compliance_client.engagement_logs["ENG-D"] = [
            EngagementAccessLogEntry(
                engagement_id="ENG-D",
                artifact_type="evidence_package",
                artifact_id="EV-77",
                accessed_at=datetime.now(UTC),
                action="view",
                ip="203.0.113.42",
            )
        ]
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/admin/auditor-engagements/ENG-D")
        assert r.status_code == 200
        # Engagement visible
        assert "ENG-D" in r.text
        # Access log entry visible (REQ-CPL-034)
        assert "EV-77" in r.text
        assert "evidence_package" in r.text


class TestEngagementsAdminRevoke:
    def test_admin_can_revoke_with_reason(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.engagements["ENG-R"] = build_engagement(
            engagement_id="ENG-R"
        )
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/admin/auditor-engagements/ENG-R/revoke",
                data={"reason": "compromise suspected; revoke immediately"},
                follow_redirects=False,
            )
        assert r.status_code == 303
        # Revoke was called and audit recorded
        assert len(fake_compliance_client.revoke_engagement_calls) == 1
        assert (
            fake_compliance_client.revoke_engagement_calls[0]["engagement_id"]
            == "ENG-R"
        )
        types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "auditor.engagement_revoked" in types
        # Underlying engagement state changed
        assert fake_compliance_client.engagements["ENG-R"].state == "revoked"

    def test_revoke_requires_reason(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.engagements["ENG-R2"] = build_engagement(
            engagement_id="ENG-R2"
        )
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(auditor_admin_router_module.router, user)
        with TestClient(app) as client:
            r = client.post(
                "/admin/auditor-engagements/ENG-R2/revoke",
                data={"reason": "short"},  # < 10 chars
            )
        assert r.status_code == 422
        # No revoke happened
        assert len(fake_compliance_client.revoke_engagement_calls) == 0


# ─── Auditor scope enforcement ────────────────────────────────────────────────


class TestRequireActiveEngagement:
    """REQ-CPL-033/034 — engagement state checks via require_active_engagement."""

    @pytest.mark.asyncio
    async def test_non_auditor_passes_through(self, make_user, fake_compliance_client):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        # Build a minimal Request with empty state
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        result = await require_active_engagement(
            req, user=user, client=fake_compliance_client
        )
        assert result is user

    @pytest.mark.asyncio
    async def test_auditor_with_active_engagement_passes(
        self, make_user, fake_compliance_client
    ):
        user = _auditor_user(make_user)
        fake_compliance_client.engagements["ENG-AUD-1"] = build_engagement(
            engagement_id="ENG-AUD-1", state="active"
        )
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        result = await require_active_engagement(
            req, user=user, client=fake_compliance_client
        )
        assert result is user
        # Engagement stashed on request.state for downstream handlers
        assert req.state.auditor_engagement.engagement_id == "ENG-AUD-1"

    @pytest.mark.asyncio
    async def test_auditor_without_engagement_record_rejected(
        self, make_user, fake_compliance_client
    ):
        """The auditor's scope references an engagement_id that doesn't exist on
        the compliance service → fail closed."""
        user = _auditor_user(make_user)
        # Don't seed engagement → fake will raise KeyError → fail closed
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        with pytest.raises(EngagementInactive) as ei:
            await require_active_engagement(
                req, user=user, client=fake_compliance_client
            )
        assert ei.value.status_code == 403
        assert ei.value.reason == "lookup_failed"

    @pytest.mark.asyncio
    async def test_revoked_engagement_rejected(
        self, make_user, fake_compliance_client
    ):
        user = _auditor_user(make_user)
        fake_compliance_client.engagements["ENG-AUD-1"] = build_engagement(
            engagement_id="ENG-AUD-1", state="revoked"
        )
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        with pytest.raises(EngagementInactive) as ei:
            await require_active_engagement(
                req, user=user, client=fake_compliance_client
            )
        assert ei.value.status_code == 403
        assert ei.value.reason == "revoked"

    @pytest.mark.asyncio
    async def test_expired_engagement_rejected_by_state(
        self, make_user, fake_compliance_client
    ):
        user = _auditor_user(make_user)
        fake_compliance_client.engagements["ENG-AUD-1"] = build_engagement(
            engagement_id="ENG-AUD-1", state="expired"
        )
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        with pytest.raises(EngagementInactive) as ei:
            await require_active_engagement(
                req, user=user, client=fake_compliance_client
            )
        assert ei.value.reason == "expired"

    @pytest.mark.asyncio
    async def test_engagement_past_end_window_rejected(
        self, make_user, fake_compliance_client
    ):
        """REQ-CPL-033 — hard expiry, no renewal. Past end-window → expired."""
        user = _auditor_user(make_user)
        # State says active, but engagement_end is in the past
        fake_compliance_client.engagements["ENG-AUD-1"] = build_engagement(
            engagement_id="ENG-AUD-1", state="active", days_remaining=-5
        )
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        with pytest.raises(EngagementInactive) as ei:
            await require_active_engagement(
                req, user=user, client=fake_compliance_client
            )
        assert ei.value.reason == "expired"

    @pytest.mark.asyncio
    async def test_auditor_without_scope_rejected(
        self, make_user, fake_compliance_client
    ):
        """An auditor with no auditor_scope at all is missing the engagement binding."""
        user = make_user(sub="aud-x", roles=[Role.AUDITOR], auditor_scope=None)
        scope = {"type": "http", "headers": [], "method": "GET", "path": "/"}
        req = Request(scope)
        with pytest.raises(EngagementInactive) as ei:
            await require_active_engagement(
                req, user=user, client=fake_compliance_client
            )
        assert ei.value.reason == "missing"


class TestEnforceArtifactScope:
    """REQ-CPL-035 — minimum-required-scope at engagement boundary."""

    def test_non_auditor_passes(self, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        # Should not raise for any artifact_type
        enforce_artifact_scope(user, artifact_type="audit_event")
        enforce_artifact_scope(user, artifact_type="anything")

    def test_auditor_in_scope_passes(self, make_user):
        user = _auditor_user(
            make_user, allowed=["audit_event", "evidence_package"]
        )
        enforce_artifact_scope(user, artifact_type="audit_event")
        enforce_artifact_scope(user, artifact_type="evidence_package")

    def test_auditor_out_of_scope_rejected(self, make_user):
        from fastapi import HTTPException

        user = _auditor_user(make_user, allowed=["audit_event"])  # only audit_event
        with pytest.raises(HTTPException) as ei:
            enforce_artifact_scope(user, artifact_type="evidence_package")
        assert ei.value.status_code == 403
        assert "outside engagement scope" in ei.value.detail


class TestLogArtifactView:
    """REQ-CPL-034 / AMD-09 — every auditor view recorded."""

    @pytest.mark.asyncio
    async def test_logs_view_for_auditor(self, make_user, fake_compliance_client):
        user = _auditor_user(make_user)
        await log_artifact_view(
            user,
            fake_compliance_client,
            artifact_type="evidence_package",
            artifact_id="EV-99",
            action="view",
        )
        # Access log entry created
        entries = fake_compliance_client.engagement_logs["ENG-AUD-1"]
        assert len(entries) == 1
        assert entries[0].artifact_type == "evidence_package"
        assert entries[0].artifact_id == "EV-99"
        assert entries[0].action == "view"
        # Audit event also recorded
        types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "auditor.artifact.view" in types

    @pytest.mark.asyncio
    async def test_non_auditor_no_log_emitted(
        self, make_user, fake_compliance_client
    ):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        await log_artifact_view(
            user,
            fake_compliance_client,
            artifact_type="evidence_package",
            artifact_id="EV-100",
        )
        # No log written
        assert fake_compliance_client.engagement_logs == {}
        assert fake_compliance_client.recorded_audit_events == []

    @pytest.mark.asyncio
    async def test_view_log_includes_engagement_id(
        self, make_user, fake_compliance_client
    ):
        """AMD-09 — engagement context is part of every view event."""
        user = _auditor_user(make_user)
        await log_artifact_view(
            user,
            fake_compliance_client,
            artifact_type="audit_event",
            artifact_id="AE-1",
        )
        evt = fake_compliance_client.recorded_audit_events[0]
        assert evt["payload"]["engagement_id"] == "ENG-AUD-1"
        assert evt["payload"]["artifact_id"] == "AE-1"
        assert evt["classification"] == "confidential"
