"""WI-15 — Outcome & Economics Views (REQ-CPL-031/032).

Read-only stakeholder dashboards for cost per outcome, quality trends, agent
economics, and forecasts with confidence intervals. All data via WI-03
ComplianceClient — portal does NO economics math.

Routes (mounted at /outcomes):

    GET /outcomes                     — overview
    GET /outcomes/cost-per-outcome    — cost view
    GET /outcomes/quality-trends      — quality view
    GET /outcomes/agent-economics     — economics view (filterable)
    GET /outcomes/forecast            — forecast view with confidence band
    GET /outcomes/export              — exportable stakeholder summary
    GET /outcomes/api/data/{view}     — JSON data endpoint for charts
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
from ..services.forecast_render import shape_for_chart, validate_band_ordering
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/outcomes", tags=["outcomes"])

_ALLOWED = (
    Role.ADMIN,
    Role.COMPLIANCE_OFFICER,
    Role.AUDITOR,
    Role.VIEWER,
)

VIEWS = ("overview", "cost", "quality", "economics", "forecast", "summary")


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _default_period() -> tuple[str, str]:
    """Default to last 30 days, ISO-8601."""
    now = datetime.now(UTC)
    start = now - timedelta(days=30)
    return start.isoformat(), now.isoformat()


def _parse_period(period_start: str | None, period_end: str | None) -> tuple[str, str]:
    if period_start is None and period_end is None:
        return _default_period()
    start, end = _default_period()
    if period_start:
        start = period_start
    if period_end:
        end = period_end
    return start, end


# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="outcomes_index")
async def outcomes_index(
    request: Request,
    period_start: str | None = None,
    period_end: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    start, end = _parse_period(period_start, period_end)
    kpis = await client.get_cost_per_outcome(start, end)
    economics = await client.get_agent_economics(start, end)
    return templates.TemplateResponse(
        request,
        "outcomes/index.html",
        {
            "user": user,
            "period_start": start,
            "period_end": end,
            "kpis": kpis,
            "top_agents": economics.items[:5],
            "crumbs": [{"label": "Outcomes"}],
        },
    )


@router.get(
    "/cost-per-outcome",
    response_class=HTMLResponse,
    name="outcomes_cost_view",
)
async def cost_view(
    request: Request,
    period_start: str | None = None,
    period_end: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    start, end = _parse_period(period_start, period_end)
    kpis = await client.get_cost_per_outcome(start, end)
    return templates.TemplateResponse(
        request,
        "outcomes/cost_view.html",
        {
            "user": user,
            "period_start": start,
            "period_end": end,
            "kpis": kpis,
        },
    )


@router.get("/sla-trends", response_class=HTMLResponse, name="outcomes_sla_trends")
async def sla_trends_view(
    request: Request,
    domain: str = "gates",
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """SLA performance over time — composes the service's derived rollup."""
    data = await client.get_sla_trends(domain=domain)
    return templates.TemplateResponse(
        request,
        "outcomes/sla_trends.html",
        {
            "user": user,
            "data": data,
            "crumbs": [{"label": "Outcomes", "href": "/outcomes"}, {"label": "SLA trends"}],
        },
    )


@router.get("/evidence-coverage", response_class=HTMLResponse, name="outcomes_evidence_coverage")
async def evidence_coverage_view(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Per-project BRD requirement coverage — composes the service's rollup."""
    data = await client.get_evidence_coverage()
    return templates.TemplateResponse(
        request,
        "outcomes/coverage.html",
        {
            "user": user,
            "data": data,
            "crumbs": [{"label": "Outcomes", "href": "/outcomes"}, {"label": "Evidence coverage"}],
        },
    )


@router.get(
    "/quality-trends",
    response_class=HTMLResponse,
    name="outcomes_quality_view",
)
async def quality_view(
    request: Request,
    period_start: str | None = None,
    period_end: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    start, end = _parse_period(period_start, period_end)
    trends = await client.get_quality_trends(start, end)
    return templates.TemplateResponse(
        request,
        "outcomes/quality_view.html",
        {
            "user": user,
            "period_start": start,
            "period_end": end,
            "trends": trends,
            "trend_values": [p.score for p in trends.points],
        },
    )


@router.get(
    "/agent-economics",
    response_class=HTMLResponse,
    name="outcomes_economics_view",
)
async def economics_view(
    request: Request,
    period_start: str | None = None,
    period_end: str | None = None,
    agent: str | None = None,
    workflow: str | None = None,
    project: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    start, end = _parse_period(period_start, period_end)
    economics = await client.get_agent_economics(
        start, end, agent=agent, workflow=workflow, project=project
    )
    return templates.TemplateResponse(
        request,
        "outcomes/economics_view.html",
        {
            "user": user,
            "period_start": start,
            "period_end": end,
            "economics": economics,
            "agent_filter": agent,
            "workflow_filter": workflow,
            "project_filter": project,
        },
    )


@router.get(
    "/forecast",
    response_class=HTMLResponse,
    name="outcomes_forecast_view",
)
async def forecast_view(
    request: Request,
    horizon_days: int = 30,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    if horizon_days < 1 or horizon_days > 365:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="horizon_days must be in [1, 365]",
        )
    forecast = await client.get_forecast_data(horizon_days=horizon_days)
    chart_data = shape_for_chart(forecast)
    band_problems = validate_band_ordering(forecast)
    if band_problems:
        logger.warning(
            "outcomes.forecast.band_inversion", problems=band_problems[:5]
        )
    return templates.TemplateResponse(
        request,
        "outcomes/forecast_view.html",
        {
            "user": user,
            "horizon_days": horizon_days,
            "forecast": forecast,
            "chart_data": chart_data,
            "band_problems": band_problems,
        },
    )


@router.get(
    "/export",
    response_class=HTMLResponse,
    name="outcomes_export",
)
async def export_view(
    request: Request,
    period_start: str | None = None,
    period_end: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    start, end = _parse_period(period_start, period_end)
    summary = await client.get_outcome_summary(start, end)
    return templates.TemplateResponse(
        request,
        "outcomes/export_partial.html",
        {
            "user": user,
            "summary": summary,
            "period_start": start,
            "period_end": end,
        },
    )


@router.get(
    "/api/data/{view}",
    response_class=JSONResponse,
    name="outcomes_data_json",
)
async def outcomes_data_json(
    view: str,
    period_start: str | None = None,
    period_end: str | None = None,
    horizon_days: int = 30,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> JSONResponse:
    if view not in VIEWS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown view: {view}",
        )
    start, end = _parse_period(period_start, period_end)
    if view == "overview":
        data = await client.get_cost_per_outcome(start, end)
    elif view == "cost":
        data = await client.get_cost_per_outcome(start, end)
    elif view == "quality":
        data = await client.get_quality_trends(start, end)
    elif view == "economics":
        data = await client.get_agent_economics(start, end)
    elif view == "forecast":
        forecast = await client.get_forecast_data(horizon_days=horizon_days)
        return JSONResponse(shape_for_chart(forecast))
    else:  # summary
        data = await client.get_outcome_summary(start, end)
    return JSONResponse(data.model_dump(mode="json"))


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — outcome_summary
# ─────────────────────────────────────────────────────────────────────────────


async def _outcome_summary_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/outcome_summary/{period_id}.

    `document_id` is interpreted as a period descriptor — we accept any
    ISO8601-compatible string and split on the literal pipe `|` if a custom
    range is given, e.g. `30d` or `2026-01-01|2026-04-01`. Default: last 30d.
    """
    from shared.api_client import ComplianceClient as _Client

    settings = get_settings()
    if document_id == "30d" or document_id in {"", "default"}:
        start, end = _default_period()
    elif "|" in document_id:
        try:
            start, end = document_id.split("|", 1)
            datetime.fromisoformat(start.replace("Z", "+00:00"))
            datetime.fromisoformat(end.replace("Z", "+00:00"))
        except (ValueError, IndexError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"bad period range: {exc}",
            ) from exc
    elif document_id.endswith("d"):
        try:
            n = int(document_id[:-1])
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"bad period spec: {document_id}",
            ) from exc
        now = datetime.now(UTC)
        start = (now - timedelta(days=n)).isoformat()
        end = now.isoformat()
    else:
        start, end = _default_period()

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
        summary = await c.get_outcome_summary(start, end)

    summary_dump = summary.model_dump(mode="json")
    kpis = summary_dump.get("kpis") or {}
    # Shape expected by portal/pdf/templates/outcome_summary.html
    outcome = {
        "id": f"outcome-{start[:10]}-{end[:10]}",
        "period": f"{start[:10]} → {end[:10]}",
        "captured_at": end,
        "narrative": (
            f"Period {start[:10]} → {end[:10]}: {kpis.get('total_outcomes', 0)} outcomes, "
            f"${kpis.get('total_cost_usd', 0):.2f} total cost, "
            f"${kpis.get('cost_per_outcome_usd', 0):.4f} per outcome, "
            f"quality score {kpis.get('quality_score', 0):.2f}, "
            f"ROI ratio {kpis.get('roi_ratio', 0):.2f}."
        ),
    }
    metrics = [
        {"name": "Total outcomes", "baseline": "—", "current": kpis.get("total_outcomes", 0), "delta": "—"},
        {"name": "Total cost (USD)", "baseline": "—", "current": f"${kpis.get('total_cost_usd', 0):.2f}", "delta": "—"},
        {"name": "Cost per outcome (USD)", "baseline": "—", "current": f"${kpis.get('cost_per_outcome_usd', 0):.4f}", "delta": "—"},
        {"name": "Quality score", "baseline": "—", "current": f"{kpis.get('quality_score', 0):.2f}", "delta": f"{kpis.get('quality_trend_pp', 0):+.2f}pp"},
        {"name": "ROI ratio", "baseline": "—", "current": f"{kpis.get('roi_ratio', 0):.2f}", "delta": "—"},
    ]
    ctx = {
        "summary": summary_dump,
        "period_start": start,
        "period_end": end,
        "outcome": outcome,
        "metrics": metrics,
        "project": "compliance-portal",
    }
    return (
        "outcome_summary.html",
        ctx,
        f"Outcome Summary {start[:10]} to {end[:10]}",
        "internal",
    )


def register_outcomes_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "outcome_summary" not in reg:
        register_component(
            "outcome_summary",
            template="outcome_summary.html",
            resolver=_outcome_summary_resolver,
            audit_event_type="outcomes.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor", "viewer"},
        )


register_outcomes_pdf_components()


__all__ = [
    "router",
    "register_outcomes_pdf_components",
    "VIEWS",
]
