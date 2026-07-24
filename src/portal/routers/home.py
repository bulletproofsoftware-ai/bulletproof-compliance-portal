"""Role-aware home / triage (composes existing read-only endpoints).

No business logic: each area is fetched independently, gated by the same RBAC
the target router enforces, and rendered as KPI + attention + activity sections.
A failing area is recorded in `errors` and skipped — never a 500.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import current_user
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..templates import get_templates

logger = get_logger(__name__)

_A, _C, _AU, _S, _V = (
    Role.ADMIN, Role.COMPLIANCE_OFFICER, Role.AUDITOR, Role.SME, Role.VIEWER,
)


async def build_home_context(client: ComplianceClient, user: User) -> dict[str, Any]:
    kpis: list[dict[str, Any]] = []
    attention: list[dict[str, Any]] = []
    activity: list[Any] = []
    errors: list[str] = []

    async def _area(name: str, roles: tuple[Role, ...], fn) -> Any:
        if roles and not user.has_any_role(*roles):
            return None
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("home.area_failed", area=name, error=str(exc))
            errors.append(name)
            return None

    gates = await _area("gates", (_A, _C), lambda: client.list_human_gates(status="pending"))
    if gates is not None:
        n = len(gates.items)
        kpis.append({"label": "Pending gates", "value": n, "href": "/gates"})
        if n:
            attention.append({"label": "Gates awaiting decision",
                              "detail": f"{n} pending", "href": "/gates", "severity": "high"})

    incidents = await _area("incidents", (_A, _C), lambda: client.list_incidents(status="open"))
    if incidents is not None:
        n = len(incidents.items)
        kpis.append({"label": "Open incidents", "value": n, "href": "/incidents"})
        if n:
            attention.append({"label": "Open incidents", "detail": f"{n} open",
                              "href": "/incidents", "severity": "high"})

    dsr = await _area("dsr", (_A, _C), lambda: client.list_dsr_requests())
    if dsr is not None:
        n = len(dsr.items)
        kpis.append({"label": "DSRs in flight", "value": n, "href": "/dsr"})
        if n:
            attention.append({"label": "Data-subject requests", "detail": f"{n} in queue",
                              "href": "/dsr", "severity": "medium"})

    knowledge = await _area("knowledge", (_A, _C, _S), lambda: client.list_knowledge_candidates())
    if knowledge is not None:
        n = len(knowledge.items)
        kpis.append({"label": "Knowledge to verify", "value": n, "href": "/knowledge"})
        if n:
            attention.append({"label": "Knowledge candidates", "detail": f"{n} awaiting review",
                              "href": "/knowledge", "severity": "medium"})

    models = await _area("models", (_A, _C, _AU, _V), lambda: client.list_model_cards())
    if models is not None:
        kpis.append({"label": "Model cards", "value": len(models), "href": "/models"})

    evidence = await _area("evidence", (_A, _C, _AU), lambda: client.list_evidence_packages())
    if evidence is not None:
        total = evidence.total if evidence.total is not None else len(evidence.items)
        kpis.append({"label": "Evidence packages", "value": total, "href": "/evidence"})

    audit = await _area("audit", (_A, _C, _AU), lambda: client.list_audit_events(limit=8))
    if audit is not None:
        activity = list(audit.items)[:8]

    return {"kpis": kpis, "attention": attention, "activity": activity, "errors": errors}


router = APIRouter(tags=["home"])


def _templates_dep() -> Jinja2Templates:
    return get_templates()


@router.get("/home", response_class=HTMLResponse, name="home_index")
async def home_index(
    request: Request,
    user: User = Depends(current_user),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    ctx = await build_home_context(client, user)
    return templates.TemplateResponse(
        request, "home/index.html", {"user": user, **ctx},
    )


@router.get("/search", response_class=HTMLResponse, name="global_search")
async def global_search_page(
    request: Request,
    q: str = "",
    user: User = Depends(current_user),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Cross-area search results. Composition only — the compliance service
    performs the actual search; the portal renders the unified hit list."""
    if q.strip():
        try:
            results = await client.global_search(q)
        except Exception as exc:  # noqa: BLE001
            logger.warning("search.failed", error=str(exc))
            results = {"query": q, "items": [], "total": 0, "error": True}
    else:
        results = {"query": q, "items": [], "total": 0}
    return templates.TemplateResponse(
        request, "search/results.html", {"user": user, "q": q, "results": results},
    )


__all__ = ["build_home_context", "router"]
