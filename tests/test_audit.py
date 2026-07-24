"""WI-04 — Audit Explorer router tests (REQ-CPL-006, AMD-07).

Covers the read-only audit explorer:
  * Page index for compliance_officer / admin / auditor
  * 403 for viewer role (not in _ALLOWED)
  * /audit/events filter parameter passing (time, user, session, type, classification)
  * /audit/events/{id} event-detail partial (hash chain pointer)
  * /audit/sessions/{id} timeline reconstruction
  * /audit/export.jsonl streams NDJSON + records initiated/completed audit events
  * /audit/verify/{id} hash-chain verification with PASS/FAIL banner data (AMD-07)
  * HTMX partial vs full-page render
  * Pagination (limit/cursor query params) flowing through to ComplianceClient
  * RBAC: viewer/sme cannot access /audit/export.jsonl
  * PDF resolver registration: "audit_event" + "session_timeline"
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import AuditorScope, Role
from portal.routers import audit as audit_router_module

from tests._fakes import build_audit_event


# ─── Fixtures ────────────────────────────────────────────────────────────────


def _auditor_user(make_user, *, allowed_artifact_types: list[str] | None = None):
    now = datetime.now(UTC)
    scope = AuditorScope(
        engagement_id="ENG-2026-A",
        engagement_start=now - timedelta(days=1),
        engagement_end=now + timedelta(days=30),
        date_range_start=now - timedelta(days=365),
        date_range_end=now,
        allowed_artifact_types=allowed_artifact_types
        or ["audit_event", "evidence_package", "gate_decision"],
        allowed_project_ids=None,
    )
    return make_user(
        sub="auditor-1",
        roles=[Role.AUDITOR],
        auditor_scope=scope,
    )


# ─── Index page — RBAC ───────────────────────────────────────────────────────


class TestAuditIndexRbac:
    def test_compliance_officer_gets_200(self, build_router_app, make_user):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit")
        assert r.status_code == 200
        assert "Audit Explorer" in r.text

    def test_admin_gets_200(self, build_router_app, make_user):
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit")
        assert r.status_code == 200

    def test_auditor_with_engagement_gets_200(self, build_router_app, make_user):
        user = _auditor_user(make_user)
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit")
        assert r.status_code == 200

    def test_viewer_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit")
        assert r.status_code == 403

    def test_sme_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.SME])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit")
        assert r.status_code == 403


# ─── /audit/events filter passing ────────────────────────────────────────────


class TestAuditEventsPartial:
    def test_filters_passed_to_client(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Spy: wrap list_audit_events to capture filters
        captured: dict = {}
        original = fake_compliance_client.list_audit_events

        async def _spy(**filters):
            captured.update(filters)
            return await original(**filters)

        fake_compliance_client.list_audit_events = _spy  # type: ignore[assignment]

        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get(
                "/audit/events",
                params={
                    "from": "2026-01-01T00:00:00Z",
                    "to": "2026-12-31T23:59:59Z",
                    "user_id": "alice",
                    "session_id": "sess-xyz",
                    "event_type": "gate.decided",
                    "classification": "confidential",
                    "limit": 25,
                },
            )
        assert r.status_code == 200
        # Verify each filter actually flowed through
        assert captured["from"] == "2026-01-01T00:00:00Z"
        assert captured["to"] == "2026-12-31T23:59:59Z"
        assert captured["user_id"] == "alice"
        assert captured["session_id"] == "sess-xyz"
        assert captured["event_type"] == "gate.decided"
        assert captured["classification"] == "confidential"
        assert captured["limit"] == 25

    def test_empty_filters_dropped(
        self, build_router_app, make_user, fake_compliance_client
    ):
        captured: dict = {}
        original = fake_compliance_client.list_audit_events

        async def _spy(**filters):
            captured.update(filters)
            return await original(**filters)

        fake_compliance_client.list_audit_events = _spy  # type: ignore[assignment]
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/events")
        assert r.status_code == 200
        # No "from" or "to" since the params were not supplied
        assert "from" not in captured
        assert "to" not in captured
        assert "user_id" not in captured
        # limit always passed (with default)
        assert captured["limit"] == 50

    def test_pagination_cursor_passed(
        self, build_router_app, make_user, fake_compliance_client
    ):
        captured: dict = {}
        original = fake_compliance_client.list_audit_events

        async def _spy(**filters):
            captured.update(filters)
            return await original(**filters)

        fake_compliance_client.list_audit_events = _spy  # type: ignore[assignment]
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/events", params={"cursor": "tok-123", "limit": 10})
        assert r.status_code == 200
        assert captured["cursor"] == "tok-123"
        assert captured["limit"] == 10

    def test_htmx_partial_does_not_render_full_page(
        self, build_router_app, make_user, fake_compliance_client
    ):
        """HX-Request → returns just the partial fragment, not full <html>."""
        fake_compliance_client.audit_events.append(
            build_audit_event(event_id="e1", chain_index=10)
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get(
                "/audit/events", headers={"HX-Request": "true"}
            )
        assert r.status_code == 200
        # Partial templates have no <html> root
        assert "<html" not in r.text.lower()
        assert "<table>" in r.text


# ─── /audit/events/{id} detail ───────────────────────────────────────────────


class TestAuditEventDetail:
    def test_returns_event_detail_partial_with_hash_chain_pointer(
        self, build_router_app, make_user, fake_compliance_client
    ):
        evt = build_audit_event(
            event_id="e-42",
            chain_index=42,
            chain_hash="hash-abc",
            prev_hash="prev-xyz",
            payload={"session_id": "sess-1"},
        )
        fake_compliance_client.audit_events.append(evt)
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/events/e-42")
        assert r.status_code == 200
        assert "e-42" in r.text
        # AMD-07 hash chain pointer surfaced
        assert "hash-abc" in r.text
        assert "prev-xyz" in r.text
        # Verify-button HTMX hook present
        assert "/audit/verify/e-42" in r.text

    def test_unknown_event_id_500_or_404(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Fake raises KeyError for unknown id (doesn't translate to HTTPException),
        # so the platform default is a 500. Either 404 or 500 is acceptable —
        # the contract is "not 200 + html for an unknown id".
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/audit/events/does-not-exist")
        assert r.status_code >= 400


# ─── /audit/sessions/{id} timeline ───────────────────────────────────────────


class TestSessionTimeline:
    def test_returns_timeline_for_session(
        self, build_router_app, make_user, fake_compliance_client
    ):
        # Seed two events in the same session
        for i in range(3):
            ev = build_audit_event(
                event_id=f"ev-{i}",
                chain_index=i,
                payload={"session_id": "sess-target"},
            )
            fake_compliance_client.audit_events.append(ev)
        # ... and one in a different session
        fake_compliance_client.audit_events.append(
            build_audit_event(
                event_id="ev-other", chain_index=99, payload={"session_id": "sess-X"}
            )
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/sessions/sess-target")
        assert r.status_code == 200
        # All 3 target-session events listed; ev-other excluded by filter
        assert "ev-0" in r.text
        assert "ev-1" in r.text
        assert "ev-2" in r.text
        assert "ev-other" not in r.text


# ─── /audit/export.jsonl ─────────────────────────────────────────────────────


class TestAuditExportJsonl:
    def test_content_type_is_ndjson(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.audit_events.append(
            build_audit_event(event_id="exp-1", chain_index=1)
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/export.jsonl")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/x-ndjson")
        assert "attachment" in r.headers.get("content-disposition", "")

    def test_export_records_initiated_and_completed_audit_events(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.audit_events.append(
            build_audit_event(event_id="exp-2", chain_index=2)
        )
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/export.jsonl")
        assert r.status_code == 200
        # Body must consume the stream — content() forces materialization
        _ = r.content
        recorded_types = [
            e["audit_type"] for e in fake_compliance_client.recorded_audit_events
        ]
        assert "audit.export.initiated" in recorded_types
        assert "audit.export.completed" in recorded_types

    def test_auditor_export_includes_watermark_metadata(
        self, build_router_app, make_user, fake_compliance_client
    ):
        fake_compliance_client.audit_events.append(
            build_audit_event(event_id="exp-3", chain_index=3)
        )
        user = _auditor_user(make_user)
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/export.jsonl")
        assert r.status_code == 200
        body = r.text
        first_line = body.splitlines()[0]
        # First line is the engagement watermark (NOT part of audit chain)
        assert "_export_meta" in first_line
        assert "ENG-2026-A" in first_line
        assert "auditor-1" in first_line

    def test_viewer_role_forbidden_on_export(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/export.jsonl")
        assert r.status_code == 403


# ─── /audit/verify/{id} (AMD-07) ─────────────────────────────────────────────


class TestAuditVerify:
    def test_service_pass_renders_PASS_banner(
        self, build_router_app, make_user, fake_compliance_client
    ):
        ev = build_audit_event(event_id="v-1", chain_index=10)
        fake_compliance_client.audit_events.append(ev)
        fake_compliance_client.hash_chain_verdict_ok = True
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/verify/v-1")
        assert r.status_code == 200
        # Banner content for PASS verdict
        assert "PASS" in r.text
        # Client-side recomputation payload included for AMD-07
        assert "verify-data-v-1" in r.text

    def test_service_fail_renders_FAIL_banner(
        self, build_router_app, make_user, fake_compliance_client
    ):
        ev = build_audit_event(event_id="v-2", chain_index=20)
        fake_compliance_client.audit_events.append(ev)
        fake_compliance_client.hash_chain_verdict_ok = False
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(audit_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/audit/verify/v-2")
        assert r.status_code == 200
        assert "FAIL" in r.text


# ─── PDF resolver registration ───────────────────────────────────────────────


class TestPdfResolverRegistration:
    def test_audit_event_resolver_registered(self):
        """Importing the audit router (already done at module top) registers
        'audit_event' on the default registry."""
        from portal.pdf.registry import get_default_registry

        # Force re-registration in case the registry was reset elsewhere
        audit_router_module.register_audit_pdf_components()
        reg = get_default_registry()
        assert "audit_event" in reg
        spec = reg.get("audit_event")
        assert spec is not None
        assert spec.audit_event_type == "audit.pdf.exported"
        assert "auditor" in spec.allowed_roles

    def test_session_timeline_resolver_registered(self):
        from portal.pdf.registry import get_default_registry

        audit_router_module.register_audit_pdf_components()
        reg = get_default_registry()
        assert "session_timeline" in reg
