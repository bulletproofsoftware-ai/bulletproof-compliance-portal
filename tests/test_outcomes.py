"""WI-15 — Outcomes & Economics router tests (REQ-CPL-031/032).

Covers:
  * Index — overview KPIs
  * Cost-per-outcome view
  * Quality trends view
  * Agent economics with filters
  * Forecast view (with band ordering validation)
  * Stakeholder export summary
  * JSON data endpoint per view
  * RBAC: viewer / admin / compliance_officer / auditor allowed; sme forbidden
  * 400 on bad horizon_days
  * 404 on unknown view
  * PDF resolver registration
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from portal.routers import outcomes as outcomes_router_module
from shared.api_client.models import (
    ComplianceTrendPoint,
    ComplianceTrends,
    ForecastData,
    ForecastPoint,
)


def _now_period() -> tuple[str, str]:
    now = datetime.now(UTC)
    return ((now - timedelta(days=30)).isoformat(), now.isoformat())


class TestOutcomesRbac:
    def test_viewer_allowed(self, build_router_app, fake_compliance_client, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 200

    def test_admin_allowed(self, build_router_app, fake_compliance_client, make_user):
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 200

    def test_compliance_officer_allowed(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 200

    def test_auditor_allowed(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.AUDITOR])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 200

    def test_sme_forbidden(self, build_router_app, fake_compliance_client, make_user):
        user = make_user(roles=[Role.SME])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 403


class TestOutcomesIndex:
    def test_index_renders_kpis(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes")
        assert r.status_code == 200
        # Default seeded KPIs from fake have $50.00 cost-per-outcome
        assert "Cost per outcome" in r.text


class TestCostView:
    def test_cost_view(self, build_router_app, fake_compliance_client, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/cost-per-outcome")
        assert r.status_code == 200
        assert "Cost per outcome" in r.text


class TestQualityView:
    def test_quality_view(self, build_router_app, fake_compliance_client, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/quality-trends")
        assert r.status_code == 200
        assert "Quality" in r.text or "quality" in r.text


class TestEconomicsView:
    def test_economics_view(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/agent-economics")
        assert r.status_code == 200
        assert "conductor-builder" in r.text

    def test_economics_with_agent_filter(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/agent-economics?agent=conductor-architect")
        assert r.status_code == 200
        assert "conductor-architect" in r.text


class TestForecastView:
    def test_forecast_view(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/forecast")
        assert r.status_code == 200
        assert "Forecast" in r.text or "forecast" in r.text

    def test_forecast_horizon_zero_400(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/forecast?horizon_days=0")
        assert r.status_code == 400

    def test_forecast_horizon_too_big_400(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/forecast?horizon_days=1000")
        assert r.status_code == 400

    def test_forecast_with_inverted_band_warns(
        self, build_router_app, fake_compliance_client, make_user
    ):
        # Seed forecast with an inverted band; router should still 200 but log
        # a warning + render anomaly notice.
        fake_compliance_client._ensure_outcomes_storage()
        now = datetime.now(UTC)
        fake_compliance_client.outcomes_forecast_storage = ForecastData(
            horizon_days=5,
            generated_at=now,
            points=[
                ForecastPoint(
                    asof=now,
                    cost_mean_usd=50.0,
                    cost_p10_usd=80.0,  # inverted!
                    cost_p90_usd=100.0,
                    quality_mean=80.0,
                    quality_p10=70.0,
                    quality_p90=90.0,
                    confidence=0.5,
                )
            ],
        )
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/forecast")
        assert r.status_code == 200
        assert "anomaly" in r.text.lower() or "ordering" in r.text.lower()


class TestExportSummary:
    def test_export_summary(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/export")
        assert r.status_code == 200


class TestDataJson:
    def test_overview_json(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/api/data/overview")
        assert r.status_code == 200
        assert "total_cost_usd" in r.json()

    def test_forecast_json(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/api/data/forecast?horizon_days=14")
        assert r.status_code == 200
        body = r.json()
        assert "labels" in body
        assert "cost" in body

    def test_unknown_view_404(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(outcomes_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/outcomes/api/data/garbage")
        assert r.status_code == 404


class TestPdfRegistration:
    def test_outcome_summary_registered(self):
        from portal.pdf.registry import get_default_registry

        outcomes_router_module.register_outcomes_pdf_components()
        reg = get_default_registry()
        assert "outcome_summary" in reg
        spec = reg.get("outcome_summary")
        assert spec is not None
        assert spec.audit_event_type == "outcomes.pdf.exported"
