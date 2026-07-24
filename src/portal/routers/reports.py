"""WI-12 — Regulatory Report Generation router (REQ-CPL-022..026).

On-demand generation of regulator-ready artifacts pulled from accumulated
evidence in the compliance service. Four report types — SOX attestation,
NY DFS Part 500, EU AI Act conformity, NAIC adverse action — each following
a five-stage workflow (draft → review → approved → signed → delivered) with
Ed25519 signing at the `signed` stage and delivery tracking.

Routes (mounted at /reports):

    GET  /reports                               — list page
    GET  /reports/new/{type}                    — type-specific form
    POST /reports/generate                      — start a draft
    GET  /reports/{report_id}                   — workflow detail
    POST /reports/{report_id}/review            — submit review (draft→review)
    POST /reports/{report_id}/approve           — approve (review→approved, SoD)
    POST /reports/{report_id}/sign              — sign (MFA + nonce)
    POST /reports/{report_id}/deliver           — record delivery

AMD-03 — sign action requires fresh MFA (60s) + decision_nonce bound to
        (user_sub, report_id). Portal NEVER computes the signature; the
        compliance service signs (Ed25519) and returns the receipt.
AMD-04 — receipt's signing_key_id resolves via the JWKS endpoint
        (/api/v1/compliance/keys/jwks.json) — verifier can validate
        independently from the portal.
AMD-08 — for PDF exports of signed reports, WI-19's `pdf_export(...)` does
        the PAdES byterange Ed25519 embedding. This router's PDF resolver
        wires the signature spec into that pipeline.
"""

from __future__ import annotations

import contextlib
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.mfa import MfaNonceManager, StepUpRequired, require_mfa
from ..auth.models import Role, User
from ..auth.rbac import require_any_role, require_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..pdf.signature import SignatureSpec
from ..services.report_workflow import (
    VALID_REPORT_TYPES,
    can_deliver,
    can_sign,
    is_valid_transition,
    valid_next_stages,
)
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

_ALLOWED_RW = (Role.ADMIN, Role.COMPLIANCE_OFFICER)
_ALLOWED_RO = (Role.ADMIN, Role.COMPLIANCE_OFFICER, Role.AUDITOR, Role.VIEWER)


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _csrf_token(request: Request) -> str:
    return request.cookies.get("csrf", "")


def _nonce_manager(request: Request) -> MfaNonceManager:
    mgr = getattr(request.app.state, "mfa_nonce_manager", None)
    if mgr is None:
        mgr = MfaNonceManager(max_age_s=60)
        request.app.state.mfa_nonce_manager = mgr
    return mgr


def _sign_action(report_id: str) -> str:
    return f"report.sign:{report_id}"


# ─────────────────────────────────────────────────────────────────────────────
# List
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="reports_index")
async def reports_index(
    request: Request,
    report_type: str | None = None,
    stage: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED_RO)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters: dict[str, Any] = {}
    if report_type:
        filters["report_type"] = report_type
    if stage:
        filters["stage"] = stage
    reports = await client.list_reports(**filters)
    return templates.TemplateResponse(
        request,
        "reports/index.html",
        {
            "user": user,
            "reports": reports,
            "is_writable": user.has_any_role(*_ALLOWED_RW),
            "kpis": [
                {"label": "Reports", "value": len(reports.items)},
                {"label": "Signed", "value": sum(1 for r in reports.items if r.signed_at)},
                {"label": "Delivered", "value": sum(1 for r in reports.items if r.stage == "delivered")},
            ],
            "crumbs": [{"label": "Reports"}],
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Generate (per-type forms)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/new/{report_type}", response_class=HTMLResponse, name="reports_new")
async def reports_new(
    request: Request,
    report_type: str,
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    if report_type not in VALID_REPORT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"unknown report_type: {report_type}"
        )
    template_map = {
        "sox_attestation": "reports/sox.html",
        "nydfs_part500": "reports/ny_dfs.html",
        "eu_ai_act_conformity": "reports/eu_ai_act.html",
        "naic_adverse_action": "reports/naic_adverse_action.html",
    }
    return templates.TemplateResponse(
        request,
        template_map[report_type],
        {"user": user, "report_type": report_type, "csrf_token": _csrf_token(request)},
    )


@router.post("/generate", response_class=HTMLResponse, name="reports_generate")
async def reports_generate(
    request: Request,
    report_type: str = Form(...),
    period_start: str = Form(default=""),
    period_end: str = Form(default=""),
    scope_notes: str = Form(default=""),
    triggering_event_id: str = Form(default=""),
    high_risk_system_change_id: str = Form(default=""),
    system_name: str = Form(default=""),
    intended_purpose: str = Form(default=""),
    linked_card_id: str = Form(default="", alias="model_card_id"),
    certifier_name: str = Form(default=""),
    certifier_title: str = Form(default=""),
    affected_party: str = Form(default=""),
    decision_summary: str = Form(default=""),
    responsible_person: str = Form(default=""),
    redress_option: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    if report_type not in VALID_REPORT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown report_type: {report_type}"
        )

    if report_type == "sox_attestation":
        if not period_start or not period_end:
            raise HTTPException(400, detail="period_start and period_end required")
        report = await client.generate_sox_report(
            period_start=period_start,
            period_end=period_end,
            scope_notes=scope_notes or None,
        )
    elif report_type == "nydfs_part500":
        if not period_start or not period_end or not certifier_name or not certifier_title:
            raise HTTPException(400, detail="period_start, period_end, certifier_name, certifier_title required")
        report = await client.generate_ny_dfs_report(
            period_start=period_start,
            period_end=period_end,
            certifier_name=certifier_name,
            certifier_title=certifier_title,
            scope_notes=scope_notes or None,
        )
    elif report_type == "eu_ai_act_conformity":
        if not high_risk_system_change_id or not system_name or not intended_purpose:
            raise HTTPException(400, detail="high_risk_system_change_id, system_name, intended_purpose required")
        report = await client.generate_eu_ai_act_report(
            high_risk_system_change_id=high_risk_system_change_id,
            system_name=system_name,
            intended_purpose=intended_purpose,
            model_card_id=linked_card_id or None,
            scope_notes=scope_notes or None,
        )
    else:  # naic_adverse_action
        if not triggering_event_id or not affected_party or not decision_summary or not responsible_person:
            raise HTTPException(400, detail="triggering_event_id, affected_party, decision_summary, responsible_person required")
        report = await client.generate_naic_adverse_action(
            triggering_event_id=triggering_event_id,
            affected_party=affected_party,
            decision_summary=decision_summary,
            responsible_person=responsible_person,
            redress_option=redress_option or None,
        )

    return templates.TemplateResponse(
        request,
        "reports/detail.html",
        {
            "user": user,
            "report": report,
            "valid_next_stages": valid_next_stages(report.stage),
            "csrf_token": _csrf_token(request),
            "is_writable": True,
            "decision_nonce": None,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Detail
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{report_id}", response_class=HTMLResponse, name="reports_detail")
async def reports_detail(
    request: Request,
    report_id: str,
    user: User = Depends(require_any_role(*_ALLOWED_RO)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    report = await client.get_report(report_id)
    is_writable = user.has_any_role(*_ALLOWED_RW)

    decision_nonce: str | None = None
    if is_writable and can_sign(report.stage):
        mgr = _nonce_manager(request)
        decision_nonce = mgr.issue(user_sub=user.sub, action=_sign_action(report_id))

    return templates.TemplateResponse(
        request,
        "reports/detail.html",
        {
            "user": user,
            "report": report,
            "valid_next_stages": valid_next_stages(report.stage),
            "csrf_token": _csrf_token(request),
            "is_writable": is_writable,
            "decision_nonce": decision_nonce,
            "can_sign": can_sign(report.stage),
            "can_deliver": can_deliver(report.stage),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stage transitions
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{report_id}/review",
    response_class=HTMLResponse,
    name="reports_review",
)
async def reports_review(
    request: Request,
    report_id: str,
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    report = await client.get_report(report_id)
    if not is_valid_transition(report.stage, "review"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot transition {report.stage} → review",
        )
    report = await client.transition_report(report_id, to_stage="review")
    return templates.TemplateResponse(
        request,
        "reports/transition_form_partial.html",
        {"user": user, "report": report},
    )


@router.post(
    "/{report_id}/approve",
    response_class=HTMLResponse,
    name="reports_approve",
)
async def reports_approve(
    request: Request,
    report_id: str,
    user: User = Depends(require_role(Role.ADMIN)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    report = await client.get_report(report_id)
    if not is_valid_transition(report.stage, "approved"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot transition {report.stage} → approved",
        )
    # SoD pre-check (REQ-CPL-026): reviewer != creator. Service is authoritative.
    if report.created_by and report.created_by == user.sub:
        with contextlib.suppress(Exception):  # best-effort audit
            await client.record_audit_event(
                audit_type="report.approve.sod_blocked",
                user_id=user.sub,
                classification="confidential",
                payload={"report_id": report_id, "creator": report.created_by},
            )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SoD: cannot approve a report you authored",
        )
    report = await client.transition_report(report_id, to_stage="approved")
    return templates.TemplateResponse(
        request,
        "reports/transition_form_partial.html",
        {"user": user, "report": report},
    )


@router.post(
    "/{report_id}/sign",
    response_class=HTMLResponse,
    name="reports_sign",
)
async def reports_sign(
    request: Request,
    report_id: str,
    decision_nonce: str = Form(...),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """AMD-03: MFA (60s) + decision_nonce bound to (user, report_id).
    AMD-04: signing_key_id returned in receipt resolves via JWKS.
    AMD-08: byterange signing applied at PDF export time (WI-19)."""
    report = await client.get_report(report_id)
    if not can_sign(report.stage):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot sign in stage {report.stage} (must be approved)",
        )

    mfa_dep = require_mfa(max_age_s=60)
    try:
        await mfa_dep(user=user)  # type: ignore[arg-type]
    except StepUpRequired:
        raise

    mgr = _nonce_manager(request)
    ok = mgr.consume(decision_nonce, user_sub=user.sub, action=_sign_action(report_id))
    if not ok:
        with contextlib.suppress(Exception):  # best-effort audit
            await client.record_audit_event(
                audit_type="auth.mfa_nonce_rejected",
                user_id=user.sub,
                classification="confidential",
                payload={
                    "report_id": report_id,
                    "nonce_fingerprint": MfaNonceManager.fingerprint(decision_nonce),
                },
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="mfa_nonce_consumed"
        )

    report = await client.sign_report(
        report_id, signed_by=user.sub, decision_nonce=decision_nonce
    )
    return templates.TemplateResponse(
        request,
        "reports/signature_block_partial.html",
        {"user": user, "report": report},
    )


@router.post(
    "/{report_id}/deliver",
    response_class=HTMLResponse,
    name="reports_deliver",
)
async def reports_deliver(
    request: Request,
    report_id: str,
    recipient: str = Form(..., min_length=1, max_length=200),
    channel: str = Form(...),
    confirmation_receipt: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    if channel not in {"email", "secure_download", "regulator_portal"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid channel: {channel}"
        )
    report = await client.get_report(report_id)
    if not can_deliver(report.stage):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"cannot deliver in stage {report.stage} (must be signed)",
        )
    delivery = await client.deliver_report(
        report_id,
        recipient=recipient,
        channel=channel,
        confirmation_receipt=confirmation_receipt or None,
    )

    # Advance to delivered after first delivery record.
    try:
        await client.transition_report(report_id, to_stage="delivered")
    except Exception as exc:  # noqa: BLE001
        logger.info("reports.deliver_already_delivered", error=str(exc))

    report = await client.get_report(report_id)
    return templates.TemplateResponse(
        request,
        "reports/delivery_log_partial.html",
        {"user": user, "report": report, "new_delivery": delivery},
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — regulatory_report (AMD-08)
# ─────────────────────────────────────────────────────────────────────────────


def _extract_signature_for_pdf(ctx: dict[str, Any]) -> SignatureSpec | None:
    """If the report has been signed, return the SignatureSpec so WI-19's
    pdf_export embeds the byterange signature (AMD-08)."""
    from datetime import UTC, datetime

    rpt = ctx.get("report") or {}
    sig_b64 = rpt.get("signature")
    key_id = rpt.get("signing_key_id")
    signed_at = rpt.get("signed_at")
    signed_by = rpt.get("signed_by")
    if not sig_b64 or not key_id or not signed_at or not signed_by:
        return None
    if isinstance(signed_at, str):
        try:
            signed_at_dt = datetime.fromisoformat(signed_at.replace("Z", "+00:00"))
        except ValueError:
            signed_at_dt = datetime.now(UTC)
    else:
        signed_at_dt = signed_at
    return SignatureSpec(
        signature=sig_b64,
        signed_at=signed_at_dt,
        signed_by=signed_by,
        signing_key_id=key_id,
    )


def _requires_pades(ctx: dict[str, Any]) -> bool:
    """Signed reports require AMD-08 byterange signing."""
    rpt = ctx.get("report") or {}
    return rpt.get("stage") in {"signed", "delivered"} and bool(rpt.get("signature"))


async def _regulatory_report_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
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
        report = await c.get_report(document_id)

    period = "—"
    if report.period_start and report.period_end:
        period = f"{report.period_start.date()} → {report.period_end.date()}"
    framework_label = {
        "sox_attestation": "SOX 404",
        "nydfs_part500": "NY DFS Part 500",
        "eu_ai_act_conformity": "EU AI Act",
        "naic_adverse_action": "NAIC Adverse Action",
    }.get(report.report_type, report.report_type)
    ctx = {
        "report": {
            "id": report.report_id,
            "report_type": report.report_type,
            "stage": report.stage,
            "period_start": report.period_start.isoformat() if report.period_start else None,
            "period_end": report.period_end.isoformat() if report.period_end else None,
            "scope_notes": report.scope_notes,
            "created_at": report.created_at.isoformat(),
            "created_by": report.created_by,
            "approved_by": report.approved_by,
            "signed_at": report.signed_at.isoformat() if report.signed_at else None,
            "signed_by": report.signed_by,
            "signature": report.signature,
            "signing_key_id": report.signing_key_id,
            "deliveries": [d.model_dump(mode="json") for d in report.deliveries],
            "transitions": report.transitions,
            # Fields the PDF template expects (portal/pdf/templates/regulatory_report.html)
            "framework": framework_label,
            "period": period,
            "deadline": report.period_end.isoformat() if report.period_end else "—",
            "status": report.stage,
            "prepared_by": report.created_by or "—",
            "approved_at": report.approved_at.isoformat() if report.approved_at else "—",
            "executive_summary": report.scope_notes or "—",
            "findings": [],
            "attestations": [
                {"section": "Signing", "actor": report.signed_by, "timestamp": report.signed_at.isoformat()}
                for _ in [None] if report.signed_at and report.signed_by
            ],
        },
        "project": "compliance-portal",
    }
    return (
        "regulatory_report.html",
        ctx,
        f"Regulatory Report {report.report_id}",
        "confidential",
    )


def register_report_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "regulatory_report" not in reg:
        register_component(
            "regulatory_report",
            template="regulatory_report.html",
            resolver=_regulatory_report_resolver,
            audit_event_type="report.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
            requires_pades=_requires_pades,
            extract_signature=_extract_signature_for_pdf,
        )


register_report_pdf_components()


__all__ = ["router", "register_report_pdf_components"]
