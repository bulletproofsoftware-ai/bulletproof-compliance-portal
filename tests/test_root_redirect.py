"""Root redirect goes to /home for authenticated users (Plan 1 Task 5)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from portal.main import create_app
from tests.conftest import _build_user


@pytest.mark.asyncio
async def test_authenticated_root_redirects_to_home():
    app = create_app(mode="internal")
    user = _build_user(roles=[Role.VIEWER])
    store = app.state.session_store
    sid = await store.create(payload={"user": user.model_dump(mode="json")}, ttl_s=3600)
    with TestClient(app) as client:
        client.cookies.set(app.state.session_cookie_name, sid)
        r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/home"


def test_home_router_mounted():
    app = create_app(mode="internal")
    paths = {route.path for route in app.routes}
    assert "/home" in paths


def test_design_system_css_served():
    app = create_app(mode="internal")
    with TestClient(app) as client:
        r = client.get("/static/css/design-system.css")
    assert r.status_code == 200
    assert ".topbar" in r.text  # class-based topbar selector (Plan 4 fix)


def test_portal_js_served_and_sortable():
    app = create_app(mode="internal")
    with TestClient(app) as client:
        r = client.get("/static/js/portal.js")
    assert r.status_code == 200
    assert "makeSortable" in r.text  # click-to-sort enhancement present
    assert "addFilter" in r.text     # find-in-table enhancement present
