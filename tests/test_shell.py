"""Sidebar shell + breadcrumbs tests (Plan 1 Task 2)."""

from __future__ import annotations

from portal.auth.models import Role
from portal.nav import nav_for
from portal.templates import get_templates
from tests.conftest import _build_user


def _render_nav(role):
    user = _build_user(roles=[role])
    tmpl = get_templates().env.get_template("_nav.html")
    return tmpl.render(nav=nav_for(user, "/home"), user=user)


def test_nav_global_registered():
    assert "nav_for" in get_templates().env.globals


def test_sidebar_shows_admin_groups():
    html = _render_nav(Role.ADMIN)
    assert "Operations" in html and "Gates" in html and "Auditors" in html


def test_sidebar_hides_operations_for_viewer():
    html = _render_nav(Role.VIEWER)
    assert "Gates" not in html
    assert "Dashboards" in html


def test_active_item_has_aria_current():
    user = _build_user(roles=[Role.ADMIN])
    tmpl = get_templates().env.get_template("_nav.html")
    html = tmpl.render(nav=nav_for(user, "/home"), user=user)
    assert 'aria-current="page"' in html
