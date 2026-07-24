"""Role-aware navigation model for the portal shell.

Pure data — no FastAPI/Jinja imports — so it is unit-testable and reusable.
`nav_for(user, current_path)` returns the sidebar groups a given user should
see, with the active item marked from the current request path. Per-item role
visibility MUST track each router's RBAC allow-list.
"""
from __future__ import annotations

from dataclasses import dataclass

from .auth.models import Role, User

_A = Role.ADMIN
_C = Role.COMPLIANCE_OFFICER
_AU = Role.AUDITOR
_S = Role.SME
_V = Role.VIEWER


@dataclass(frozen=True)
class NavItem:
    label: str
    href: str
    roles: tuple[Role, ...] = ()  # empty = all authenticated
    active: bool = False


@dataclass(frozen=True)
class NavGroup:
    label: str
    items: tuple[NavItem, ...]


# Declarative definition; order = render order. Roles mirror the RBAC matrix.
_NAV: tuple[tuple[str, tuple[NavItem, ...]], ...] = (
    ("Overview", (
        NavItem("Home", "/home"),
        NavItem("Dashboards", "/dashboards", (_A, _C, _AU, _V)),
    )),
    ("Operations", (
        NavItem("Gates", "/gates", (_A, _C)),
        NavItem("Incidents", "/incidents", (_A, _C)),
        NavItem("DSR", "/dsr", (_A, _C)),
    )),
    ("Evidence & Trust", (
        NavItem("Evidence", "/evidence", (_A, _C, _AU)),
        NavItem("Audit", "/audit", (_A, _C, _AU)),
        NavItem("Reports", "/reports", (_A, _C, _AU, _V)),
    )),
    ("Knowledge & Models", (
        NavItem("Knowledge", "/knowledge", (_A, _C, _S)),
        NavItem("Model Cards", "/models", (_A, _C, _AU, _V)),
    )),
    ("Outcomes", (
        NavItem("Outcomes", "/outcomes", (_A, _C, _AU, _V)),
    )),
    ("Admin", (
        NavItem("Projects", "/projects", (_A, _C, _AU, _V)),
        NavItem("Auditors", "/admin/auditor-engagements", (_A,)),
    )),
)


def _visible(item_roles: tuple[Role, ...], user: User) -> bool:
    return True if not item_roles else user.has_any_role(*item_roles)


def _is_active(href: str, current_path: str) -> bool:
    return current_path == href or current_path.startswith(href + "/")


def nav_for(user: User, current_path: str) -> list[NavGroup]:
    groups: list[NavGroup] = []
    for label, items in _NAV:
        visible = tuple(
            NavItem(it.label, it.href, it.roles, _is_active(it.href, current_path))
            for it in items
            if _visible(it.roles, user)
        )
        if visible:
            groups.append(NavGroup(label, visible))
    return groups


__all__ = ["NavItem", "NavGroup", "nav_for"]
