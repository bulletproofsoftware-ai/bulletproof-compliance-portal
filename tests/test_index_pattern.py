"""Index-pattern rollout tests (Plan 2): page header, KPI cards, breadcrumbs."""

from __future__ import annotations

from fastapi.testclient import TestClient

from portal.auth.models import Role


def test_gates_index_has_kpis_and_breadcrumbs(build_router_app, fake_compliance_client, make_user):
    from portal.routers import gates as gates_module

    user = make_user(roles=[Role.ADMIN])
    app = build_router_app(gates_module.router, user)
    with TestClient(app) as client:
        r = client.get("/gates")
    assert r.status_code == 200
    assert "Gate Decisions" in r.text          # page_header
    assert "kpi-grid" in r.text                # kpi_cards rendered
    assert "Pending" in r.text                 # a KPI label
    assert 'aria-label="Breadcrumb"' in r.text  # breadcrumbs macro


def _index_app(build_router_app, make_user, module, role=Role.ADMIN):
    return build_router_app(module.router, make_user(roles=[role]))


def test_incidents_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import incidents as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/incidents")
    assert r.status_code == 200
    assert "Incidents" in r.text and "kpi-grid" in r.text
    assert "High/critical" in r.text and 'aria-label="Breadcrumb"' in r.text


def test_evidence_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import evidence as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/evidence")
    assert r.status_code == 200
    assert "Evidence Packages" in r.text and "kpi-grid" in r.text
    assert "Signed" in r.text and 'aria-label="Breadcrumb"' in r.text


def test_dsr_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import dsr as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/dsr")
    assert r.status_code == 200
    assert "DSR Queue" in r.text and "kpi-grid" in r.text
    assert "In queue" in r.text and 'aria-label="Breadcrumb"' in r.text


def test_reports_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import reports as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/reports")
    assert r.status_code == 200
    assert "Regulatory Reports" in r.text and "kpi-grid" in r.text
    assert 'aria-label="Breadcrumb"' in r.text


def test_model_cards_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import model_cards as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/models")
    assert r.status_code == 200
    assert "Model Card Registry" in r.text and "kpi-grid" in r.text
    assert 'aria-label="Breadcrumb"' in r.text


def test_knowledge_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import process_knowledge as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/knowledge")
    assert r.status_code == 200
    assert "Process Knowledge Verification" in r.text and "kpi-grid" in r.text
    assert 'aria-label="Breadcrumb"' in r.text


def test_audit_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import audit as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/audit")
    assert r.status_code == 200
    assert "Audit Explorer" in r.text and 'aria-label="Breadcrumb"' in r.text


def test_dashboards_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import dashboards as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/dashboards")
    assert r.status_code == 200
    assert "Compliance Dashboards" in r.text and "kpi-grid" in r.text
    assert 'aria-label="Breadcrumb"' in r.text


def test_projects_index_pattern(build_router_app, fake_compliance_client, make_user):
    from portal.routers import project_docs as m
    with TestClient(_index_app(build_router_app, make_user, m)) as client:
        r = client.get("/projects")
    assert r.status_code == 200
    assert "Projects" in r.text and "kpi-grid" in r.text
    assert 'aria-label="Breadcrumb"' in r.text


def test_dashboards_compare_view(build_router_app, fake_compliance_client, make_user):
    """Cross-framework comparison route renders and ranks frameworks."""
    from datetime import UTC, datetime
    from portal.routers import dashboards as m
    from shared.api_client.models import ComplianceScores, ComplianceDomainScore
    fake_compliance_client._ensure_dashboards_storage()
    fake_compliance_client.compliance_scores_storage["iso42001"] = ComplianceScores(
        framework="iso42001", overall_score=88.0, asof=datetime.now(UTC),
        domain_scores=[ComplianceDomainScore(domain="gov", score=88.0)], regression_flag=False)
    user = make_user(roles=[Role.ADMIN])
    app = build_router_app(m.router, user)
    with TestClient(app) as client:
        r = client.get("/dashboards/compare")
    assert r.status_code == 200
    assert "Framework Comparison" in r.text
    assert "88.0" in r.text and "ISO/IEC 42001" in r.text
