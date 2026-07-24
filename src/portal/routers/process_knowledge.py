"""WI-14 — Process Knowledge Verification Queue (REQ-CPL-029/030).

HTMX UI for SME review of knowledge candidates extracted from trajectories /
sessions / documents. Routes are SME-only — viewers and auditors are denied.

Routes (mounted at /knowledge):

    GET  /knowledge                                — queue (filtered by status)
    GET  /knowledge/types/{type}                   — filter by knowledge type
    GET  /knowledge/{candidate_id}                 — candidate detail page
    GET  /knowledge/{candidate_id}/diff            — YAML diff partial
    POST /knowledge/{candidate_id}/approve         — approve into KB
    POST /knowledge/{candidate_id}/reject          — reject with rationale
    POST /knowledge/{candidate_id}/modify          — SME modify + approve
    POST /knowledge/batch                          — REQ-CPL-030 batch operations

Validation:

    * Rationale >= 30 chars (SME accountability)
    * Modified YAML must pass services/yaml_validator before being
      forwarded to the compliance service
    * Knowledge type must be in {rule, decision_tree, sop, edge_case}
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..services.yaml_diff import diff_summary, render_diff
from ..services.yaml_validator import validate_candidate_yaml
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/knowledge", tags=["knowledge"])

# REQ-CPL-029 — SME role required. Admin and compliance_officer can also act
# (admin override; compliance_officer drives queue throughput).
_ALLOWED = (Role.SME, Role.ADMIN, Role.COMPLIANCE_OFFICER)

KNOWLEDGE_TYPES = ("rule", "decision_tree", "sop", "edge_case")
MIN_RATIONALE_CHARS = 30


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _ensure_rationale(rationale: str) -> str:
    if not rationale or len(rationale.strip()) < MIN_RATIONALE_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"rationale must be >= {MIN_RATIONALE_CHARS} chars",
        )
    return rationale.strip()


def _ensure_knowledge_type(t: str) -> str:
    if t not in KNOWLEDGE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown knowledge_type: {t}",
        )
    return t


# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="knowledge_index")
async def knowledge_index(
    request: Request,
    candidate_status: str | None = "pending",
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters: dict[str, Any] = {}
    if candidate_status:
        filters["status"] = candidate_status
    candidates = await client.list_knowledge_candidates(**filters)
    return templates.TemplateResponse(
        request,
        "knowledge/index.html",
        {
            "user": user,
            "candidates": candidates,
            "candidate_status": candidate_status,
            "knowledge_types": KNOWLEDGE_TYPES,
            "kpis": [
                {"label": "Candidates", "value": candidates.total or len(candidates.items)},
                {"label": "Pending", "value": sum(1 for c in candidates.items if c.status == "pending")},
            ],
            "crumbs": [{"label": "Knowledge"}],
        },
    )


@router.get(
    "/types/{knowledge_type}",
    response_class=HTMLResponse,
    name="knowledge_by_type",
)
async def knowledge_by_type(
    request: Request,
    knowledge_type: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    knowledge_type = _ensure_knowledge_type(knowledge_type)
    candidates = await client.list_candidates_by_type(knowledge_type)
    return templates.TemplateResponse(
        request,
        "knowledge/index.html",
        {
            "user": user,
            "candidates": candidates,
            "candidate_status": None,
            "knowledge_type_filter": knowledge_type,
            "knowledge_types": KNOWLEDGE_TYPES,
        },
    )


@router.get(
    "/{candidate_id}",
    response_class=HTMLResponse,
    name="knowledge_candidate_detail",
)
async def candidate_detail(
    request: Request,
    candidate_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    candidate = await client.get_knowledge_candidate(candidate_id)
    diff = render_diff(candidate.existing_yaml, candidate.proposed_yaml)
    summary = diff_summary(diff)
    return templates.TemplateResponse(
        request,
        "knowledge/candidate_detail.html",
        {
            "user": user,
            "candidate": candidate,
            "diff": diff,
            "diff_summary": summary,
            "min_rationale": MIN_RATIONALE_CHARS,
        },
    )


@router.get(
    "/{candidate_id}/diff",
    response_class=HTMLResponse,
    name="knowledge_candidate_diff",
)
async def candidate_diff(
    request: Request,
    candidate_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    candidate = await client.get_knowledge_candidate(candidate_id)
    diff = render_diff(candidate.existing_yaml, candidate.proposed_yaml)
    summary = diff_summary(diff)
    return templates.TemplateResponse(
        request,
        "knowledge/diff_partial.html",
        {
            "user": user,
            "candidate": candidate,
            "diff": diff,
            "diff_summary": summary,
        },
    )


@router.post(
    "/{candidate_id}/approve",
    response_class=HTMLResponse,
    name="knowledge_candidate_approve",
)
async def candidate_approve(
    request: Request,
    candidate_id: str,
    rationale: str = Form(...),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    rationale = _ensure_rationale(rationale)
    updated = await client.approve_candidate(
        candidate_id, rationale=rationale, decided_by=user.sub
    )
    return templates.TemplateResponse(
        request,
        "knowledge/decision_partial.html",
        {"user": user, "candidate": updated, "action": "approved"},
    )


@router.post(
    "/{candidate_id}/reject",
    response_class=HTMLResponse,
    name="knowledge_candidate_reject",
)
async def candidate_reject(
    request: Request,
    candidate_id: str,
    rationale: str = Form(...),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    rationale = _ensure_rationale(rationale)
    updated = await client.reject_candidate(
        candidate_id, rationale=rationale, decided_by=user.sub
    )
    return templates.TemplateResponse(
        request,
        "knowledge/decision_partial.html",
        {"user": user, "candidate": updated, "action": "rejected"},
    )


@router.post(
    "/{candidate_id}/modify",
    response_class=HTMLResponse,
    name="knowledge_candidate_modify",
)
async def candidate_modify(
    request: Request,
    candidate_id: str,
    modified_yaml: str = Form(...),
    rationale: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    candidate = await client.get_knowledge_candidate(candidate_id)
    validation = validate_candidate_yaml(modified_yaml, candidate.knowledge_type)
    if not validation.ok:
        return templates.TemplateResponse(
            request,
            "knowledge/modify_editor.html",
            {
                "user": user,
                "candidate": candidate,
                "modified_yaml": modified_yaml,
                "errors": validation.errors,
            },
            status_code=422,
        )
    rationale_clean = rationale.strip() if rationale else ""
    if rationale_clean and len(rationale_clean) < MIN_RATIONALE_CHARS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"rationale must be >= {MIN_RATIONALE_CHARS} chars when provided",
        )
    updated = await client.modify_candidate(
        candidate_id,
        modified_yaml=modified_yaml,
        modified_by=user.sub,
        rationale=rationale_clean or None,
    )
    return templates.TemplateResponse(
        request,
        "knowledge/decision_partial.html",
        {"user": user, "candidate": updated, "action": "modified"},
    )


@router.post(
    "/batch",
    response_class=HTMLResponse,
    name="knowledge_candidate_batch",
)
async def candidate_batch(
    request: Request,
    candidate_ids: str = Form(default=""),  # comma-separated
    action: str = Form(...),
    rationale: str = Form(...),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-030 — batch approve/reject."""
    # An empty candidate_ids field must reach this handler so it returns the
    # documented 400 ("no candidate_ids provided") rather than a framework 422.
    # Starlette >= 1.0 rejects empty values for required Form fields before the
    # handler body runs, so the empty-string case is normalised below.
    if action not in {"approve", "reject"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid batch action: {action}",
        )
    rationale = _ensure_rationale(rationale)
    ids = [s.strip() for s in candidate_ids.split(",") if s.strip()]
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="no candidate_ids provided",
        )
    if len(ids) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="batch size capped at 100",
        )
    result = await client.batch_process_candidates(
        candidate_ids=ids,
        action=action,
        rationale=rationale,
        decided_by=user.sub,
    )
    return templates.TemplateResponse(
        request,
        "knowledge/batch_result.html",
        {"user": user, "result": result, "action": action},
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — process_knowledge
# ─────────────────────────────────────────────────────────────────────────────


async def _process_knowledge_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/process_knowledge/{candidate_id}."""
    from shared.api_client import ComplianceClient as _Client

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
        candidate = await c.get_knowledge_candidate(document_id)

    diff = render_diff(candidate.existing_yaml, candidate.proposed_yaml)
    diff_lines = [
        {"kind": dl.kind, "text": dl.text} for dl in diff
    ]
    ctx = {
        "candidate": candidate.model_dump(mode="json"),
        "diff": diff_lines,
        "diff_summary": diff_summary(diff),
        # Shape expected by portal/pdf/templates/process_knowledge.html
        "entry": {
            "id": candidate.candidate_id,
            "title": (candidate.proposed_yaml or "")[:80] or candidate.candidate_id,
            "domain": candidate.domain,
            "version": "v1",
            "owner": candidate.decided_by or candidate.assigned_to or "—",
            "last_reviewed_at": (candidate.decided_at.isoformat() if candidate.decided_at else "—"),
            "description": candidate.rationale or candidate.proposed_yaml or "—",
            "decision_tree": None,
        },
        "project": "compliance-portal",
    }
    return (
        "process_knowledge.html",
        ctx,
        f"Knowledge Candidate {candidate.candidate_id}",
        "confidential",
    )


def register_process_knowledge_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "process_knowledge" not in reg:
        register_component(
            "process_knowledge",
            template="process_knowledge.html",
            resolver=_process_knowledge_resolver,
            audit_event_type="process_knowledge.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "sme"},
        )


register_process_knowledge_pdf_components()


__all__ = [
    "router",
    "register_process_knowledge_pdf_components",
    "KNOWLEDGE_TYPES",
    "MIN_RATIONALE_CHARS",
]
