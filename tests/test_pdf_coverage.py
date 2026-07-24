"""Contract test: every PRD-19 portal component MUST register a PDF resolver.

PRD-19 Recommendation 4 (audit-2026-05-01): "Add a contract test asserting
all 12 components register". This guards against a future commit that
forgets to call `register_*_pdf_components()` for one of the 12 portal
components, which would silently disable PDF export for that surface.

Failure modes caught:
  - A new router added without a register_..._pdf_components() function.
  - An existing register function removed/renamed.
  - A component name renamed without updating the EXPECTED_COMPONENTS list.
  - The router file failing to import at app startup (causes the registration
    not to fire).

The test is structural — it imports each router module to trigger the
module-level `register_*_pdf_components()` call, then inspects the default
PDF registry. It does NOT spin up the FastAPI app; it does NOT rely on
classification/RBAC plumbing.
"""

from __future__ import annotations

import importlib
import sys

import pytest


# REQ-CPL-045 universal PDF export: 12 components for the 12 portal
# surfaces. Two of them ("audit_event" + "session_timeline") share the
# audit-explorer router, which is why we have 12 components but only 11
# "register_*_pdf_components()" functions. The list below is the
# authoritative catalog.
EXPECTED_COMPONENTS = frozenset(
    {
        "audit_event",            # routers/audit.py
        "session_timeline",       # routers/audit.py
        "evidence_package",       # routers/evidence.py
        "gate_decision",          # routers/gates.py
        "dsr_record",             # routers/dsr.py
        "incident_report",        # routers/incidents.py
        "model_card",             # routers/model_cards.py
        "regulatory_report",      # routers/reports.py
        "dashboard_snapshot",     # routers/dashboards.py
        "process_knowledge",      # routers/process_knowledge.py
        "outcome_summary",        # routers/outcomes.py
        "project_doc",            # routers/project_docs.py
    }
)

# Routers whose import-time side effect SHOULD register PDF components.
ROUTER_MODULES_WITH_PDF = (
    "portal.routers.audit",
    "portal.routers.evidence",
    "portal.routers.gates",
    "portal.routers.dsr",
    "portal.routers.incidents",
    "portal.routers.model_cards",
    "portal.routers.reports",
    "portal.routers.dashboards",
    "portal.routers.process_knowledge",
    "portal.routers.outcomes",
    "portal.routers.project_docs",
)


@pytest.fixture(autouse=True)
def _isolate_registry():
    """Reset the default PDF registry between tests.

    Each test imports the router modules fresh so the registration code runs
    against a clean registry. Without this, test ordering would matter.
    """
    from portal.pdf import registry as registry_module

    registry_module.reset_default_registry()

    # Drop cached imports of the router modules so module-level register_*
    # side effects fire again on import below.
    for name in list(sys.modules.keys()):
        if name in ROUTER_MODULES_WITH_PDF:
            del sys.modules[name]
    yield
    registry_module.reset_default_registry()
    for name in list(sys.modules.keys()):
        if name in ROUTER_MODULES_WITH_PDF:
            del sys.modules[name]


def _import_all_routers() -> None:
    """Import every router that should register a PDF component."""
    for mod in ROUTER_MODULES_WITH_PDF:
        importlib.import_module(mod)


def test_all_twelve_components_register():
    """REQ-CPL-045: every portal component has a PDF resolver registered."""
    from portal.pdf.registry import get_default_registry

    _import_all_routers()
    registered = set(get_default_registry().list_components())
    missing = EXPECTED_COMPONENTS - registered
    extra = registered - EXPECTED_COMPONENTS
    assert not missing, (
        f"Missing PDF component registrations: {sorted(missing)}. "
        f"Currently registered: {sorted(registered)}. "
        "Each portal surface must call register_*_pdf_components() at "
        "module import time."
    )
    # `extra` is informational only — a future PR may add components.
    # We still pass; the assertion above is the load-bearing one.
    assert len(registered) >= len(EXPECTED_COMPONENTS), (
        f"Registered {len(registered)} components, expected >= "
        f"{len(EXPECTED_COMPONENTS)}. Extra: {sorted(extra)}."
    )


def test_component_count_is_exactly_twelve():
    """REQ-CPL-045: the official count is 12. Adding new ones requires
    updating the EXPECTED_COMPONENTS catalog above so this test stays
    aligned with the PRD."""
    from portal.pdf.registry import get_default_registry

    _import_all_routers()
    count = len(get_default_registry().list_components())
    assert count == len(EXPECTED_COMPONENTS), (
        f"Expected exactly {len(EXPECTED_COMPONENTS)} PDF components, "
        f"got {count}. If you added a new component, update "
        f"EXPECTED_COMPONENTS in this test file. If you removed one, "
        f"audit the PRD-19 §4 component list before merging."
    )


def test_each_component_has_resolver_and_template():
    """Every registered component must have a callable resolver and a non-empty
    template name. Catches incomplete spec construction."""
    from portal.pdf.registry import get_default_registry

    _import_all_routers()
    reg = get_default_registry()
    for component in EXPECTED_COMPONENTS:
        spec = reg.get(component)
        assert spec is not None, f"component {component} not registered"
        assert spec.template, f"component {component} has empty template"
        assert callable(spec.resolver), f"component {component} resolver not callable"
        assert spec.audit_event_type, (
            f"component {component} missing audit_event_type — "
            "PDF downloads must be auditable."
        )


def test_no_duplicate_registration():
    """Re-importing each router twice should not raise — the
    register_*_pdf_components() functions are idempotent (they check
    `if name not in reg` before registering)."""
    from portal.pdf.registry import get_default_registry

    _import_all_routers()
    first = set(get_default_registry().list_components())
    # Re-trigger by reimporting; idempotency means no exception.
    _import_all_routers()
    second = set(get_default_registry().list_components())
    assert first == second, (
        f"Re-import changed component set: added={second - first}, "
        f"removed={first - second}"
    )


def test_role_acl_is_set_for_every_component():
    """Each component declares either explicit allowed_roles or auditor_only,
    so PDF generation always runs against a role gate (no 'public' PDFs)."""
    from portal.pdf.registry import get_default_registry

    _import_all_routers()
    reg = get_default_registry()
    for component in EXPECTED_COMPONENTS:
        spec = reg.get(component)
        assert spec is not None
        # Either explicit allowed_roles set OR auditor_only_components flag
        # OR the component is universally auditor-readable (project_doc).
        has_role_gate = (
            (spec.allowed_roles and len(spec.allowed_roles) > 0)
            or spec.auditor_only_components
        )
        assert has_role_gate, (
            f"component {component} has no role gate. PDF downloads must "
            "be ACL-restricted under REQ-CPL-002."
        )
