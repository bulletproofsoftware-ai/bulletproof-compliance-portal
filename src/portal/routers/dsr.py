"""WI-08 — DSR Management router (internal).

Internal HTMX UI for compliance officers to manage GDPR Data Subject Requests
through their full lifecycle. Implements REQ-CPL-012/013/014/015 plus CISO
amendments AMD-01 (state machine + SoD), AMD-12 (token invalidation on close),
and AMD-16 (atomic mark-used delivery tokens — service authoritative).

Routes (mounted at /dsr):

    GET  /dsr                                     — queue page
    GET  /dsr/queue                               — queue partial (HTMX)
    GET  /dsr/{req_id}                            — detail page
    POST /dsr/{req_id}/transition                 — state transition
    POST /dsr/{req_id}/generate-evidence          — start filtered evidence pkg
    POST /dsr/{req_id}/deliver                    — issue delivery token
    POST /dsr/{req_id}/close                      — close (invalidates tokens)

The portal does NOT compute identity verification; the service is authoritative.
The portal records the verification method/notes and renders the state machine.

AMD-01 SoD pre-check
====================
A reviewer (current_user) cannot identity-verify a DSR they themselves
submitted — pre-checked here, authoritatively enforced by the compliance
service. The portal disables the verify action when `dsr.submitted_by ==
current_user.sub`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..services.dsr_sla import remaining_days, sla_band
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/dsr", tags=["dsr"])

_ALLOWED = (Role.ADMIN, Role.COMPLIANCE_OFFICER)

# Valid state transitions (pre-check; service is authoritative).
# AMD-01 inserts identity_pending between received and verified.
_VALID_TRANSITIONS = {
    "received": {"identity_pending", "rejected"},
    "identity_pending": {
        "verified",
        "identity_insufficient",
        "identity_rejected",
        "rejected",
    },
    "identity_insufficient": {
        "identity_pending",
        "identity_rejected",
        "rejected",
    },
    "verified": {"processing", "rejected"},
    "processing": {"evidence_generated", "rejected"},
    "evidence_generated": {"delivered", "rejected"},
    "delivered": {"closed", "rejected"},
    # terminal states
    "closed": set(),
    "rejected": set(),
    "identity_rejected": set(),
}

_TERMINAL_STATES = frozenset({"closed", "rejected", "identity_rejected"})


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _is_terminal(status_str: str) -> bool:
    return status_str in _TERMINAL_STATES


def _csrf_token(request: Request) -> str:
    return request.cookies.get("csrf", "")


# ─────────────────────────────────────────────────────────────────────────────
# Queue
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="dsr_index")
async def dsr_index(
    request: Request,
    request_type: str | None = None,
    status_filter: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters: dict[str, Any] = {}
    if request_type:
        filters["request_type"] = request_type
    if status_filter:
        filters["status"] = status_filter
    requests_list = await client.list_dsr_requests(**filters)
    now = datetime.now(UTC)

    # Decorate with SLA band/remaining for the template.
    decorated = []
    for r in requests_list.items:
        rem = remaining_days(r.submitted_at, now=now)
        decorated.append(
            {
                "request": r,
                "remaining_days": rem,
                "remaining_int": int(rem),
                "band": sla_band(rem),
                "is_terminal": _is_terminal(r.status),
                "is_self_submitted": r.submitted_by == user.sub if r.submitted_by else False,
            }
        )
    # Sort by remaining ascending (most urgent first).
    decorated.sort(key=lambda d: d["remaining_days"])

    kpis = [
        {"label": "In queue", "value": len(decorated)},
        {"label": "Overdue", "value": sum(1 for d in decorated if d["remaining_days"] <= 0)},
        {"label": "Due ≤7d", "value": sum(1 for d in decorated if 0 < d["remaining_days"] <= 7)},
    ]
    return templates.TemplateResponse(
        request,
        "dsr/index.html",
        {
            "user": user,
            "rows": decorated,
            "request_type_filter": request_type,
            "status_filter": status_filter,
            "kpis": kpis,
            "crumbs": [{"label": "DSR"}],
        },
    )


@router.get("/queue", response_class=HTMLResponse, name="dsr_queue_partial")
async def dsr_queue_partial(
    request: Request,
    request_type: str | None = None,
    status_filter: str | None = None,
    escalation: bool = False,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """HTMX partial — used for auto-refresh (every 60s) and for the worker
    job to fetch escalation candidates (escalation=true filters to <=7d remaining)."""
    filters: dict[str, Any] = {}
    if request_type:
        filters["request_type"] = request_type
    if status_filter:
        filters["status"] = status_filter
    requests_list = await client.list_dsr_requests(**filters)
    now = datetime.now(UTC)

    decorated = []
    for r in requests_list.items:
        rem = remaining_days(r.submitted_at, now=now)
        if escalation and (rem > 7 or rem < 0):
            continue
        decorated.append(
            {
                "request": r,
                "remaining_days": rem,
                "remaining_int": int(rem),
                "band": sla_band(rem),
                "is_terminal": _is_terminal(r.status),
                "is_self_submitted": r.submitted_by == user.sub if r.submitted_by else False,
            }
        )
    decorated.sort(key=lambda d: d["remaining_days"])

    return templates.TemplateResponse(
        request,
        "dsr/queue_partial.html",
        {"user": user, "rows": decorated},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Detail
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{req_id}", response_class=HTMLResponse, name="dsr_detail")
async def dsr_detail(
    request: Request,
    req_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    dsr = await client.get_dsr_request(req_id)
    rem = remaining_days(dsr.submitted_at)
    band = sla_band(rem)

    # AMD-01 SoD pre-check — disable identity-verify when submitter == reviewer.
    sod_violation = bool(dsr.submitted_by) and dsr.submitted_by == user.sub
    valid_next = sorted(_VALID_TRANSITIONS.get(dsr.status, set()))

    return templates.TemplateResponse(
        request,
        "dsr/detail.html",
        {
            "user": user,
            "dsr": dsr,
            "remaining_days": rem,
            "remaining_int": int(rem),
            "band": band,
            "valid_next_states": valid_next,
            "is_terminal": _is_terminal(dsr.status),
            "sod_violation": sod_violation,
            "csrf_token": _csrf_token(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Transition
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{req_id}/transition",
    response_class=HTMLResponse,
    name="dsr_transition",
)
async def dsr_transition(
    request: Request,
    req_id: str,
    to_status: str = Form(...),
    notes: str = Form(default=""),
    rejection_reason: str = Form(default=""),
    verification_method: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    dsr = await client.get_dsr_request(req_id)

    # Pre-check transition validity.
    valid_next = _VALID_TRANSITIONS.get(dsr.status, set())
    if to_status not in valid_next:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid transition: {dsr.status} → {to_status}",
        )

    # Separation-of-duties pre-check on identity-verification action.
    if (
        to_status in {"verified", "identity_insufficient", "identity_rejected"}
        and dsr.submitted_by
        and dsr.submitted_by == user.sub
    ):
        try:
            await client.record_audit_event(
                audit_type="dsr.identity_review.sod_blocked",
                user_id=user.sub,
                classification="confidential",
                payload={
                    "request_id": req_id,
                    "submitted_by": dsr.submitted_by,
                    "attempted_to_status": to_status,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("dsr.sod_audit_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SoD violation: cannot identity-verify a DSR you submitted",
        )

    # Required-field gate.
    if to_status == "rejected" and not rejection_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rejection_reason is required when transitioning to rejected",
        )
    if to_status == "verified" and not verification_method:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="verification_method is required when transitioning to verified",
        )

    result = await client.transition_dsr_status(
        req_id,
        to_status=to_status,
        notes=notes or None,
        rejection_reason=rejection_reason or None,
        verification_method=verification_method or None,
    )

    # Re-fetch the DSR for re-render with updated state.
    dsr = await client.get_dsr_request(req_id)

    return templates.TemplateResponse(
        request,
        "dsr/transition_form_partial.html",
        {
            "user": user,
            "dsr": dsr,
            "transition_result": result,
            "valid_next_states": sorted(_VALID_TRANSITIONS.get(dsr.status, set())),
            "is_terminal": _is_terminal(dsr.status),
            "csrf_token": _csrf_token(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Generate evidence
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{req_id}/generate-evidence",
    response_class=HTMLResponse,
    name="dsr_generate_evidence",
)
async def dsr_generate_evidence(
    request: Request,
    req_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    dsr = await client.get_dsr_request(req_id)
    if dsr.status not in {"verified", "processing"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot generate evidence in state {dsr.status}",
        )

    job = await client.generate_dsr_evidence(req_id)
    # Audit emission (service writes too — this is portal breadcrumb).
    try:
        await client.record_audit_event(
            audit_type="dsr.evidence.generation_requested",
            user_id=user.sub,
            classification="confidential",
            payload={"request_id": req_id, "job_id": job.job_id},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("dsr.evidence_audit_failed", error=str(exc))

    return templates.TemplateResponse(
        request,
        "dsr/evidence_panel_partial.html",
        {"user": user, "dsr": dsr, "job": job},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Deliver — AMD-16 atomic mark-used (service-side)
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{req_id}/deliver",
    response_class=HTMLResponse,
    name="dsr_deliver",
)
async def dsr_deliver(
    request: Request,
    req_id: str,
    package_id: str = Form(...),
    version: str = Form(default="v1"),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    dsr = await client.get_dsr_request(req_id)
    if dsr.status not in {"evidence_generated"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot deliver in state {dsr.status}",
        )

    # The compliance service issues the token and atomically marks it used on
    # consume (AMD-16). The portal never holds the signing secret.
    token = await client.deliver_dsr(req_id, package_id=package_id, version=version)

    try:
        await client.record_audit_event(
            audit_type="dsr.delivery_token.issued",
            user_id=user.sub,
            classification="confidential",
            payload={
                "request_id": req_id,
                "package_id": package_id,
                "version": version,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("dsr.delivery_audit_failed", error=str(exc))

    return templates.TemplateResponse(
        request,
        "dsr/delivery_link_partial.html",
        {"user": user, "dsr": dsr, "token": token},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Close — AMD-12 invalidate outstanding delivery tokens
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{req_id}/close",
    response_class=HTMLResponse,
    name="dsr_close",
)
async def dsr_close(
    request: Request,
    req_id: str,
    acknowledged_at: str = Form(default=""),
    acknowledgment_method: str = Form(default="email"),
    notes: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    dsr = await client.get_dsr_request(req_id)
    if dsr.status != "delivered":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot close in state {dsr.status}",
        )

    # Service atomically invalidates outstanding delivery tokens (AMD-12).
    result = await client.close_dsr(
        req_id,
        acknowledged_at=acknowledged_at or None,
        acknowledgment_method=acknowledgment_method,
        notes=notes or None,
    )

    # Audit: AMD-12 mandated event.
    try:
        await client.record_audit_event(
            audit_type="dsr.token.invalidated_on_close",
            user_id=user.sub,
            classification="confidential",
            payload={
                "request_id": req_id,
                "token_count": result.invalidated_token_count,
                "closed_by": user.sub,
                "closed_at": result.transitioned_at.isoformat(),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("dsr.close_audit_failed", error=str(exc))

    dsr = await client.get_dsr_request(req_id)
    return templates.TemplateResponse(
        request,
        "dsr/transition_form_partial.html",
        {
            "user": user,
            "dsr": dsr,
            "transition_result": result,
            "valid_next_states": [],
            "is_terminal": True,
            "csrf_token": _csrf_token(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — REQ-CPL-045 (DSR record PDF export)
# ─────────────────────────────────────────────────────────────────────────────


async def _dsr_record_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/dsr_record/{req_id}."""
    from shared.api_client import ComplianceClient as _Client

    from ..config import get_settings

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
        dsr = await c.get_dsr_request(document_id)

    rem = remaining_days(dsr.submitted_at)
    transitions = list(dsr.transitions or [])
    activity_log = [
        {
            "timestamp": t.get("transitioned_at") or t.get("timestamp"),
            "action": f"{t.get('from_status','?')} → {t.get('to_status','?')}",
            "actor": t.get("transitioned_by") or "system",
            "notes": t.get("notes") or "",
        }
        for t in transitions if isinstance(t, dict)
    ]
    ctx = {
        "dsr": {
            "id": dsr.request_id,
            "request_type": dsr.request_type,
            "status": dsr.status,
            "submitted_at": dsr.submitted_at.isoformat(),
            "remaining_days": rem,
            "subject_email": dsr.subject_email,
            "subject_name": dsr.subject_name,
            "source": dsr.source,
            "transitions": dsr.transitions,
            "notes": dsr.notes,
        },
        # Shape expected by portal/pdf/templates/dsr_record.html
        "request": {
            "id": dsr.request_id,
            "request_type": dsr.request_type,
            "status": dsr.status,
            "submitted_at": dsr.submitted_at.isoformat(),
            "closed_at": dsr.closed_at.isoformat() if dsr.closed_at else "—",
            "sla_deadline": dsr.sla_deadline.isoformat() if dsr.sla_deadline else f"{rem}d remaining",
            "verification_status": "verified" if dsr.identity_proof_id else "pending",
            "subject_redacted": f"{dsr.subject_name or '[REDACTED]'} <{dsr.subject_email or '[REDACTED]'}>",
        },
        "activity_log": activity_log,
        "project": "compliance-portal",
    }
    return (
        "dsr_record.html",
        ctx,
        f"DSR Record {dsr.request_id}",
        "confidential",
    )


def register_dsr_pdf_components() -> None:
    """Register dsr_record on the default registry. Idempotent."""
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "dsr_record" not in reg:
        register_component(
            "dsr_record",
            template="dsr_record.html",
            resolver=_dsr_record_resolver,
            audit_event_type="dsr.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )


register_dsr_pdf_components()


__all__ = ["router", "register_dsr_pdf_components"]
