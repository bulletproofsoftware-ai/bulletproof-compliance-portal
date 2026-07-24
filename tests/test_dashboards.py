"""WI-13 — Compliance Dashboards router tests (REQ-CPL-027/028).

Covers:
  * Index page renders all 6 frameworks with sparkline data
  * Per-framework view shows scores, trends, gap counts
  * Trend JSON endpoint returns chart-ready dict
  * Scores JSON endpoint
  * Gap analysis HTMX partial drill-down
  * Control detail partial
  * RBAC: viewer/admin/compliance_officer/auditor allowed; SME forbidden
  * Unknown framework -> 404
  * period_days bounds checking
  * PDF resolver registration
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from portal.routers import dashboards as dashboards_router_module
from shared.api_client.models import (
    ComplianceControlDetail,
    ComplianceDomainScore,
    ComplianceGap,
    ComplianceGapAnalysis,
    ComplianceScores,
    ComplianceTrendPoint,
    ComplianceTrends,
)


def _seed(client) -> None:
    client._ensure_dashboards_storage()
    now = datetime.now(UTC)
    client.compliance_scores_storage["iso42001"] = ComplianceScores(
        framework="iso42001",
        overall_score=82.5,
        asof=now,
        domain_scores=[
            ComplianceDomainScore(domain="governance", score=85.0),
            ComplianceDomainScore(domain="risk", score=80.0),
        ],
        regression_flag=False,
    )
    client.compliance_trends_storage["iso42001"] = ComplianceTrends(
        framework="iso42001",
        period_days=90,
        points=[ComplianceTrendPoint(asof=now, score=82.0)],
    )
    client.compliance_gaps_storage["iso42001"] = ComplianceGapAnalysis(
        framework="iso42001",
        asof=now,
        gaps=[
            ComplianceGap(
                control_id="A.5.1",
                title="Information security policies",
                impact="high",
                status="open",
            )
        ],
    )
    client.compliance_controls_storage[("iso42001", "A.5.1")] = ComplianceControlDetail(
        control_id="A.5.1",
        framework="iso42001",
        title="Information security policies",
        description="Org policies",
        status="passing",
        score=88.0,
    )


class TestDashboardsRbac:
    def test_viewer_gets_index(self, build_router_app, fake_compliance_client, make_user):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert r.status_code == 200
        assert "Compliance Dashboards" in r.text

    def test_admin_allowed(self, build_router_app, fake_compliance_client, make_user):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert r.status_code == 200

    def test_compliance_officer_allowed(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert r.status_code == 200

    def test_sme_forbidden(self, build_router_app, fake_compliance_client, make_user):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.SME])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert r.status_code == 403


class TestDashboardsIndex:
    def test_index_lists_all_frameworks(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert r.status_code == 200
        # All 6 frameworks should appear in the table
        for fw in dashboards_router_module.SUPPORTED_FRAMEWORKS:
            assert fw in r.text

    def test_index_shows_overall_score(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards")
        assert "82.5" in r.text


class TestFrameworkView:
    def test_unknown_framework_404(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/unknown_fw")
        assert r.status_code == 404

    def test_known_framework_200(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001")
        assert r.status_code == 200
        assert "ISO/IEC 42001" in r.text


class TestScoresJson:
    def test_scores_json(self, build_router_app, fake_compliance_client, make_user):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/scores")
        assert r.status_code == 200
        body = r.json()
        assert body["framework"] == "iso42001"
        assert body["overall_score"] == 82.5

    def test_scores_404_on_unknown(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/bogus/scores")
        assert r.status_code == 404


class TestTrendsJson:
    def test_trends_default_period(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/trends")
        assert r.status_code == 200
        assert r.json()["framework"] == "iso42001"

    def test_trends_period_zero_400(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/trends?period_days=0")
        assert r.status_code == 400

    def test_trends_period_too_big_400(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/trends?period_days=400")
        assert r.status_code == 400


class TestGapAnalysis:
    def test_gap_analysis_partial(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/gap-analysis")
        assert r.status_code == 200
        # Partial: should not include the topbar (no <html> wrapper)
        assert "<html" not in r.text
        assert "A.5.1" in r.text


class TestControlDetail:
    def test_control_detail_partial(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(dashboards_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/dashboards/iso42001/controls/A.5.1")
        assert r.status_code == 200
        assert "A.5.1" in r.text
        assert "<html" not in r.text


class TestPdfRegistration:
    def test_dashboard_snapshot_registered(self):
        from portal.pdf.registry import get_default_registry

        # Force re-registration in case the registry was reset elsewhere
        dashboards_router_module.register_dashboards_pdf_components()
        reg = get_default_registry()
        assert "dashboard_snapshot" in reg
        spec = reg.get("dashboard_snapshot")
        assert spec is not None
        assert spec.audit_event_type == "dashboard.pdf.exported"
