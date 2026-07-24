"""Role-aware navigation model tests (Plan 1 Task 1)."""

from __future__ import annotations

from portal.auth.models import Role
from portal.nav import nav_for
from tests.conftest import _build_user


def _labels(groups):
    return {g.label: [i.label for i in g.items] for g in groups}


def test_admin_sees_all_groups():
    user = _build_user(roles=[Role.ADMIN])
    groups = nav_for(user, "/home")
    labels = _labels(groups)
    assert "Operations" in labels and "Gates" in labels["Operations"]
    assert "Auditors" in labels["Admin"]


def test_viewer_cannot_see_operations_or_auditors():
    user = _build_user(roles=[Role.VIEWER])
    labels = _labels(nav_for(user, "/home"))
    assert "Operations" not in labels
    assert "Auditors" not in labels.get("Admin", [])
    assert "Dashboards" in labels["Overview"]
    assert "Model Cards" in labels["Knowledge & Models"]


def test_sme_sees_knowledge_not_dashboards():
    labels = _labels(nav_for(_build_user(roles=[Role.SME]), "/home"))
    assert "Knowledge" in labels["Knowledge & Models"]
    assert "Dashboards" not in labels.get("Overview", [])


def test_active_item_marked_for_nested_path():
    groups = nav_for(_build_user(roles=[Role.ADMIN]), "/evidence/PKG-1")
    evidence = next(i for g in groups for i in g.items if i.href == "/evidence")
    home = next(i for g in groups for i in g.items if i.href == "/home")
    assert evidence.active is True
    assert home.active is False
