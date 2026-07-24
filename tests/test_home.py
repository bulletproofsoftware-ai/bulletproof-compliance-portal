"""Home triage tests (Plan 1 Tasks 3-4)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from shared.api_client.models import HumanGate, Incident


def _seed_ops(fake):
    now = datetime.now(UTC)
    fake.gates = {
        "g1": HumanGate(
            gate_id="g1", title="Deploy approval",
            classification="internal", status="pending", requested_at=now,
        ),
    }
    fake._ensure_incidents_storage()
    fake.incidents_storage["INC-0001"] = Incident(
        incident_id="INC-0001", title="Data leak",
        severity="high", status="open", detected_at=now,
    )


@pytest.mark.asyncio
async def test_compliance_officer_attention_has_gates_and_incidents(
    fake_compliance_client, make_user
):
    from portal.routers.home import build_home_context

    _seed_ops(fake_compliance_client)
    ctx = await build_home_context(
        fake_compliance_client, make_user(roles=[Role.COMPLIANCE_OFFICER])
    )
    hrefs = [a["href"] for a in ctx["attention"]]
    assert "/gates" in hrefs
    assert "/incidents" in hrefs


@pytest.mark.asyncio
async def test_viewer_has_no_operations_attention(fake_compliance_client, make_user):
    from portal.routers.home import build_home_context

    _seed_ops(fake_compliance_client)
    ctx = await build_home_context(
        fake_compliance_client, make_user(roles=[Role.VIEWER])
    )
    hrefs = [a["href"] for a in ctx["attention"]]
    assert "/gates" not in hrefs and "/incidents" not in hrefs


@pytest.mark.asyncio
async def test_area_failure_is_isolated(fake_compliance_client, make_user):
    from portal.routers.home import build_home_context

    async def boom(**_):
        raise RuntimeError("backend down")

    fake_compliance_client.list_human_gates = boom  # type: ignore[assignment]
    ctx = await build_home_context(
        fake_compliance_client, make_user(roles=[Role.ADMIN])
    )
    assert "gates" in ctx["errors"]
    assert isinstance(ctx["attention"], list)


class TestHomeRoute:
    def test_home_renders_for_viewer(self, build_router_app, fake_compliance_client, make_user):
        from portal.routers import home as home_module

        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(home_module.router, user)
        with TestClient(app) as client:
            r = client.get("/home")
        assert r.status_code == 200
        assert "Needs your attention" in r.text

    def test_home_shows_gates_attention_for_officer(
        self, build_router_app, fake_compliance_client, make_user
    ):
        from portal.routers import home as home_module

        _seed_ops(fake_compliance_client)
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(home_module.router, user)
        with TestClient(app) as client:
            r = client.get("/home")
        assert r.status_code == 200
        assert "/gates" in r.text
