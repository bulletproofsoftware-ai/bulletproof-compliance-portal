"""Global cross-area search route + top-bar box."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from portal.auth.models import Role
from shared.api_client.models import AuditEvent


def _app(build_router_app, make_user):
    from portal.routers import home as m
    return build_router_app(m.router, make_user(roles=[Role.VIEWER]))


def test_search_page_empty_query(build_router_app, fake_compliance_client, make_user):
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/search")
    assert r.status_code == 200
    assert "Search" in r.text  # page renders the search form


def test_search_returns_matching_hits(build_router_app, fake_compliance_client, make_user):
    fake_compliance_client.audit_events = [
        AuditEvent(event_id="ev-deploy-1", audit_type="deploy.approved",
                   user_id="u1", classification="internal", ts=datetime.now(UTC))
    ]
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/search", params={"q": "deploy"})
    assert r.status_code == 200
    assert "deploy.approved" in r.text       # the audit hit surfaces
    assert "result(s) for" in r.text


def test_topbar_has_search_box(build_router_app, fake_compliance_client, make_user):
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/home")
    assert r.status_code == 200
    assert 'class="topbar-search"' in r.text
    assert 'action="/search"' in r.text
