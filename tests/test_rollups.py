"""SLA-trends and evidence-coverage rollup views."""

from __future__ import annotations

from fastapi.testclient import TestClient

from portal.auth.models import Role


def _app(build_router_app, make_user, role=Role.ADMIN):
    from portal.routers import outcomes as m
    return build_router_app(m.router, make_user(roles=[role]))


def test_sla_trends_view(build_router_app, fake_compliance_client, make_user):
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/outcomes/sla-trends")
    assert r.status_code == 200
    assert "SLA Trends" in r.text
    assert "2026-W20" in r.text          # a bucketed period from the rollup
    assert "On-time rate" in r.text


def test_evidence_coverage_view(build_router_app, fake_compliance_client, make_user):
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/outcomes/evidence-coverage")
    assert r.status_code == 200
    assert "Evidence Coverage" in r.text
    assert "proj-a" in r.text            # a project row from the rollup
    assert "Overall coverage" in r.text


def test_sla_trends_empty_state(build_router_app, fake_compliance_client, make_user):
    fake_compliance_client.sla_trends_payload = {"domain": "gates", "sla_hours": 24, "points": [], "total": 0}
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/outcomes/sla-trends")
    assert r.status_code == 200
    assert "No decision history yet." in r.text


def test_coverage_viewer_allowed(build_router_app, fake_compliance_client, make_user):
    with TestClient(_app(build_router_app, make_user, role=Role.VIEWER)) as client:
        r = client.get("/outcomes/evidence-coverage")
    assert r.status_code == 200
