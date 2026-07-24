"""WI-13 — Compliance Dashboards (REQ-CPL-027/028).

Multi-framework compliance scoring views. Fetches from the compliance service
via WI-03 ComplianceClient and renders Chart.js / inline-SVG visualizations.
Read-only; no decision capture in the portal.

Frameworks supported:

    iso42001          ISO/IEC 42001 AIMS
    eu_ai_act         EU AI Act conformity
    owasp_agentic     OWASP Top 10 for Agentic Apps
    soc2              SOC 2 Trust Service Criteria
    iso27001          ISO/IEC 27001 Annex A
    glba              GLBA Safeguards Rule

Routes (mounted at /dashboards):

    GET /dashboards                                   — landing + framework grid
    GET /dashboards/{framework}                       — per-framework detail
    GET /dashboards/{framework}/scores                — JSON for charts
    GET /dashboards/{framework}/trends                — JSON trend data
    GET /dashboards/{framework}/gap-analysis          — gap analysis drill-down
    GET /dashboards/{framework}/controls/{control_id} — control detail
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/dashboards", tags=["dashboards"])

_ALLOWED = (
    Role.ADMIN,
    Role.COMPLIANCE_OFFICER,
    Role.AUDITOR,
    Role.VIEWER,
)

SUPPORTED_FRAMEWORKS = (
    "iso42001",
    "eu_ai_act",
    "owasp_agentic",
    "soc2",
    "iso27001",
    "glba",
)

FRAMEWORK_LABELS = {
    "iso42001": "ISO/IEC 42001 AIMS",
    "eu_ai_act": "EU AI Act",
    "owasp_agentic": "OWASP Top 10 (Agentic)",
    "soc2": "SOC 2 TSC",
    "iso27001": "ISO/IEC 27001 Annex A",
    "glba": "GLBA Safeguards",
}


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _ensure_framework(framework: str) -> str:
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown framework: {framework}",
        )
    return framework


# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="dashboards_index")
async def dashboards_index(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Landing page — six-framework grid with sparkline + score for each."""
    framework_data: list[dict[str, Any]] = []
    for fw in SUPPORTED_FRAMEWORKS:
        try:
            scores = await client.get_compliance_scores(fw)
            trends = await client.get_compliance_trends(fw, period_days=90)
        except Exception as exc:  # noqa: BLE001
            logger.warning("dashboards.fetch_failed", framework=fw, error=str(exc))
            scores = None
            trends = None
        framework_data.append(
            {
                "framework": fw,
                "label": FRAMEWORK_LABELS[fw],
                "scores": scores,
                "trends": trends,
                "trend_values": [p.score for p in trends.points] if trends else [],
            }
        )
    kpis = [
        {"label": "Frameworks", "value": len(framework_data)},
        {"label": "Regressions", "value": sum(
            1 for f in framework_data if f["scores"] and f["scores"].regression_flag)},
        {"label": "Unavailable", "value": sum(1 for f in framework_data if not f["scores"])},
    ]
    return templates.TemplateResponse(
        request,
        "dashboards/index.html",
        {
            "user": user,
            "frameworks": framework_data,
            "kpis": kpis,
            "crumbs": [{"label": "Dashboards"}],
        },
    )


@router.get("/compare", response_class=HTMLResponse, name="dashboards_compare")
async def dashboards_compare(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Side-by-side comparison of overall scores across all frameworks.

    Composition only — fetches each framework's existing scores and ranks them;
    no new aggregation in the portal or the service.
    """
    rows: list[dict[str, Any]] = []
    for fw in SUPPORTED_FRAMEWORKS:
        try:
            scores = await client.get_compliance_scores(fw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("dashboards.compare.fetch_failed", framework=fw, error=str(exc))
            scores = None
        rows.append(
            {
                "framework": fw,
                "label": FRAMEWORK_LABELS[fw],
                "overall": scores.overall_score if scores else None,
                "regression": bool(scores.regression_flag) if scores else False,
                "domains": len(scores.domain_scores) if scores else 0,
                "asof": scores.asof if scores else None,
            }
        )
    ranked = sorted(rows, key=lambda r: (r["overall"] is None, -(r["overall"] or 0)))
    return templates.TemplateResponse(
        request,
        "dashboards/compare.html",
        {
            "user": user,
            "rows": ranked,
            "crumbs": [{"label": "Dashboards", "href": "/dashboards"}, {"label": "Compare"}],
        },
    )


@router.get(
    "/{framework}",
    response_class=HTMLResponse,
    name="dashboards_framework_view",
)
async def framework_view(
    request: Request,
    framework: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    framework = _ensure_framework(framework)
    scores = await client.get_compliance_scores(framework)
    trends = await client.get_compliance_trends(framework, period_days=90)
    gaps = await client.get_gap_analysis(framework)
    return templates.TemplateResponse(
        request,
        "dashboards/framework_view.html",
        {
            "user": user,
            "framework": framework,
            "framework_label": FRAMEWORK_LABELS[framework],
            "scores": scores,
            "trends": trends,
            "gaps": gaps,
            "trend_values": [p.score for p in trends.points],
            "domain_labels": [d.domain for d in scores.domain_scores],
            "domain_values": [d.score for d in scores.domain_scores],
        },
    )


@router.get(
    "/{framework}/scores",
    response_class=JSONResponse,
    name="dashboards_scores_json",
)
async def scores_json(
    framework: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> JSONResponse:
    framework = _ensure_framework(framework)
    scores = await client.get_compliance_scores(framework)
    return JSONResponse(scores.model_dump(mode="json"))


@router.get(
    "/{framework}/trends",
    response_class=JSONResponse,
    name="dashboards_trends_json",
)
async def trends_json(
    framework: str,
    period_days: int = 90,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> JSONResponse:
    framework = _ensure_framework(framework)
    if period_days < 1 or period_days > 365:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="period_days must be in [1, 365]",
        )
    trends = await client.get_compliance_trends(framework, period_days=period_days)
    return JSONResponse(trends.model_dump(mode="json"))


@router.get(
    "/{framework}/gap-analysis",
    response_class=HTMLResponse,
    name="dashboards_gap_analysis",
)
async def gap_analysis(
    request: Request,
    framework: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    framework = _ensure_framework(framework)
    gaps = await client.get_gap_analysis(framework)
    return templates.TemplateResponse(
        request,
        "dashboards/gap_analysis_partial.html",
        {
            "user": user,
            "framework": framework,
            "framework_label": FRAMEWORK_LABELS[framework],
            "gaps": gaps,
        },
    )


@router.get(
    "/{framework}/controls/{control_id}",
    response_class=HTMLResponse,
    name="dashboards_control_detail",
)
async def control_detail(
    request: Request,
    framework: str,
    control_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    framework = _ensure_framework(framework)
    control = await client.get_control_detail(framework, control_id)
    return templates.TemplateResponse(
        request,
        "dashboards/control_detail.html",
        {
            "user": user,
            "framework": framework,
            "framework_label": FRAMEWORK_LABELS[framework],
            "control": control,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — dashboard_snapshot
# ─────────────────────────────────────────────────────────────────────────────


async def _dashboard_snapshot_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/dashboard_snapshot/{framework}."""
    from shared.api_client import ComplianceClient as _Client

    framework = document_id
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown framework: {framework}",
        )

    settings = get_settings()
    async with _Client(
        base_url=str(settings.compliance_api_base_url),
        token=settings.compliance_api_token.get_secret_value(),
        timeout_s=settings.compliance_api_timeout_s,
        user_sub=user.sub,
        request_id=None,
        auditor_scope=user.auditor_scope.model_dump(mode="json")
        if user.auditor_scope
        else None,
    ) as c:
        scores = await c.get_compliance_scores(framework)
        trends = await c.get_compliance_trends(framework, period_days=90)
        gaps = await c.get_gap_analysis(framework)

    scores_dump = scores.model_dump(mode="json")
    trends_dump = trends.model_dump(mode="json")
    gaps_dump = gaps.model_dump(mode="json")
    # Shape expected by portal/pdf/templates/dashboard_snapshot.html
    snapshot = {
        "id": f"{framework}-{scores_dump.get('asof', '')[:10]}",
        "period": "Last 90 days",
        "captured_at": scores_dump.get("asof") or "—",
    }
    metrics = [
        {"name": "Overall score", "value": f"{scores_dump.get('overall_score', 0):.2f}", "trend": "—"},
        *(
            {"name": d.get("domain", "domain"), "value": f"{d.get('score', 0):.2f}", "trend": "—"}
            for d in scores_dump.get("domain_scores", [])
        ),
    ]
    open_items = [
        {
            "title": g.get("title") or g.get("control_id"),
            "severity": g.get("impact", "medium"),
            "owner": g.get("assignee") or "—",
        }
        for g in gaps_dump.get("gaps", [])
    ]
    ctx = {
        "framework": framework,
        "framework_label": FRAMEWORK_LABELS[framework],
        "scores": scores_dump,
        "trends": trends_dump,
        "gaps": gaps_dump,
        "snapshot": snapshot,
        "metrics": metrics,
        "open_items": open_items,
        "project": "compliance-portal",
    }
    return (
        "dashboard_snapshot.html",
        ctx,
        f"Dashboard Snapshot: {FRAMEWORK_LABELS[framework]}",
        "internal",
    )


def register_dashboards_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "dashboard_snapshot" not in reg:
        register_component(
            "dashboard_snapshot",
            template="dashboard_snapshot.html",
            resolver=_dashboard_snapshot_resolver,
            audit_event_type="dashboard.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor", "viewer"},
        )


register_dashboards_pdf_components()


__all__ = [
    "router",
    "register_dashboards_pdf_components",
    "SUPPORTED_FRAMEWORKS",
    "FRAMEWORK_LABELS",
]
