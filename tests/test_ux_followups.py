"""UX follow-ups: audit-detail modal + collapsed-by-default filters."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from portal.auth.models import Role
from shared.api_client.models import AuditEvent


def _app(build_router_app, make_user, module, role=Role.ADMIN):
    return build_router_app(module.router, make_user(roles=[role]))


def test_base_has_reusable_modal(build_router_app, fake_compliance_client, make_user):
    from portal.routers import audit as m
    with TestClient(_app(build_router_app, make_user, m)) as client:
        r = client.get("/audit")
    assert r.status_code == 200
    assert 'id="cp-modal"' in r.text
    assert 'id="cp-modal-body"' in r.text


def test_audit_view_opens_modal_not_bottom_panel(build_router_app, fake_compliance_client, make_user):
    from portal.routers import audit as m
    fake_compliance_client.audit_events = [
        AuditEvent(event_id="e1", audit_type="gate.decided", user_id="u1",
                   classification="internal", ts=datetime.now(UTC), chain_index=1)
    ]
    with TestClient(_app(build_router_app, make_user, m)) as client:
        r = client.get("/audit/events")
    assert r.status_code == 200
    assert 'hx-target="#cp-modal-body"' in r.text   # detail pops into the modal
    assert "#audit-detail" not in r.text             # no longer the bottom panel


def test_audit_filters_collapsed_by_default(build_router_app, fake_compliance_client, make_user):
    from portal.routers import audit as m
    with TestClient(_app(build_router_app, make_user, m)) as client:
        r = client.get("/audit")
    assert "<details" in r.text
    assert "<details open" not in r.text   # collapsed, not expanded
    assert 'name="event_type"' in r.text   # the filter form is inside


def test_dsr_filters_collapsed_by_default(build_router_app, fake_compliance_client, make_user):
    from portal.routers import dsr as m
    with TestClient(_app(build_router_app, make_user, m)) as client:
        r = client.get("/dsr")
    assert "<details" in r.text
    assert "<details open" not in r.text


def test_knowledge_filters_collapsed_by_default(build_router_app, fake_compliance_client, make_user):
    from portal.routers import process_knowledge as m
    with TestClient(_app(build_router_app, make_user, m)) as client:
        r = client.get("/knowledge")
    assert "<details" in r.text
    assert "<details open" not in r.text
