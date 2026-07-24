"""WI-11 — Model Card Registry router (REQ-CPL-019/020/021).

HTMX UI for PRD-18 model cards: registry, detail, annual review scheduling,
and the 5-step review workflow with sign-off (Ed25519 signature returned by
the compliance service per AMD-03 — MFA per-decision binding via decision_nonce,
60s freshness).

Routes (mounted at /models):

    GET  /models                                  — registry list
    GET  /models/{model_id}                       — model detail
    POST /models/{model_id}/review/start          — schedule a review
    POST /models/{model_id}/review/{review_id}/transition
    POST /models/{model_id}/review/{review_id}/sign-off (MFA + nonce)
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
from ..auth.rbac import require_any_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..services.review_schedule import review_band, upcoming_reminders
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/models", tags=["model_cards"])

_ALLOWED_RW = (Role.ADMIN, Role.COMPLIANCE_OFFICER)
_ALLOWED_RO = (Role.ADMIN, Role.COMPLIANCE_OFFICER, Role.AUDITOR, Role.VIEWER)

_VALID_REVIEW_TRANSITIONS = {
    "scheduled": {"evidence_assembly"},
    "evidence_assembly": {"reviewer_assigned"},
    "reviewer_assigned": {"decision"},
    "decision": {"signed_off"},
    "signed_off": set(),
}


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


def _signoff_action(review_id: str) -> str:
    return f"model_review.signoff:{review_id}"


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="model_cards_index")
async def model_cards_index(
    request: Request,
    family: str | None = None,
    risk_tier: int | None = None,
    user: User = Depends(require_any_role(*_ALLOWED_RO)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters: dict[str, Any] = {}
    if family:
        filters["family"] = family
    if risk_tier:
        filters["risk_tier"] = risk_tier
    cards = await client.list_model_cards(**filters)

    decorated = []
    for c in cards:
        b = review_band(c.next_review_date) if c.next_review_date else "green"
        decorated.append({"card": c, "band": b})

    return templates.TemplateResponse(
        request,
        "model_cards/index.html",
        {
            "user": user,
            "rows": decorated,
            "kpis": [
                {"label": "Models", "value": len(decorated)},
                {"label": "Review due", "value": sum(1 for d in decorated if d["band"] in ("red", "amber", "overdue"))},
                {"label": "High tier (3+)", "value": sum(1 for d in decorated if (d["card"].risk_tier or 0) >= 3)},
            ],
            "crumbs": [{"label": "Model Cards"}],
        },
    )


@router.get("/{model_id}", response_class=HTMLResponse, name="model_card_detail")
async def model_card_detail(
    request: Request,
    model_id: str,
    user: User = Depends(require_any_role(*_ALLOWED_RO)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    card = await client.get_model_card(model_id)

    # Issue decision nonces upfront for any review currently in `decision` state
    # (so the sign-off form can reference one bound to user+review).
    nonces: dict[str, str] = {}
    if user.has_any_role(*_ALLOWED_RW):
        mgr = _nonce_manager(request)
        for review in card.reviews:
            if review.state == "decision":
                nonces[review.review_id] = mgr.issue(
                    user_sub=user.sub, action=_signoff_action(review.review_id)
                )

    reminders = (
        upcoming_reminders(card.next_review_date) if card.next_review_date else []
    )

    return templates.TemplateResponse(
        request,
        "model_cards/detail.html",
        {
            "user": user,
            "card": card,
            "review_band": review_band(card.next_review_date)
            if card.next_review_date
            else "green",
            "reminders": reminders,
            "nonces": nonces,
            "is_writable": user.has_any_role(*_ALLOWED_RW),
            "csrf_token": _csrf_token(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Review workflow
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{model_id}/review/start",
    response_class=HTMLResponse,
    name="model_review_start",
)
async def model_review_start(
    request: Request,
    model_id: str,
    scheduled_for: str = Form(...),
    primary_reviewer_sub: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    review = await client.schedule_model_review(
        model_id,
        scheduled_for=scheduled_for,
        primary_reviewer_sub=primary_reviewer_sub or None,
    )
    card = await client.get_model_card(model_id)
    return templates.TemplateResponse(
        request,
        "model_cards/review_form_partial.html",
        {"user": user, "card": card, "review": review},
    )


@router.post(
    "/{model_id}/review/{review_id}/transition",
    response_class=HTMLResponse,
    name="model_review_transition",
)
async def model_review_transition(
    request: Request,
    model_id: str,
    review_id: str,
    to_state: str = Form(...),
    decision: str = Form(default=""),
    rationale: str = Form(default=""),
    evidence_package_id: str = Form(default=""),
    external_url: str = Form(default=""),
    external_label: str = Form(default=""),
    reviewer_sub: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    # Find current review state so we can validate
    card = await client.get_model_card(model_id)
    review = next((r for r in card.reviews if r.review_id == review_id), None)
    if review is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"review {review_id} not found"
        )
    valid_next = _VALID_REVIEW_TRANSITIONS.get(review.state, set())
    if to_state not in valid_next:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid review transition: {review.state} → {to_state}",
        )

    if to_state == "decision":
        if not rationale or len(rationale) < 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="rationale must be >= 30 characters for decision step",
            )
        if decision not in {"approve", "defer", "escalate"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid decision: {decision}",
            )

    review = await client.transition_model_review(
        model_id,
        review_id,
        to_state=to_state,
        decision=decision or None,
        rationale=rationale or None,
        evidence_package_id=evidence_package_id or None,
        external_url=external_url or None,
        external_label=external_label or None,
        reviewer_sub=reviewer_sub or None,
    )
    card = await client.get_model_card(model_id)
    return templates.TemplateResponse(
        request,
        "model_cards/review_form_partial.html",
        {"user": user, "card": card, "review": review},
    )


@router.post(
    "/{model_id}/review/{review_id}/sign-off",
    response_class=HTMLResponse,
    name="model_review_signoff",
)
async def model_review_signoff(
    request: Request,
    model_id: str,
    review_id: str,
    decision_nonce: str = Form(...),
    user: User = Depends(require_any_role(*_ALLOWED_RW)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """AMD-03 — sign-off requires fresh MFA (60s) + valid decision_nonce
    bound to (user, review_id). The compliance service produces the Ed25519
    signature; portal NEVER computes it."""
    # 1. Require fresh MFA (max age 60s).
    mfa_dep = require_mfa(max_age_s=60)
    try:
        await mfa_dep(user=user)  # type: ignore[arg-type]
    except StepUpRequired:
        raise

    # 2. Consume nonce (single-use, bound to user + review).
    mgr = _nonce_manager(request)
    ok = mgr.consume(
        decision_nonce, user_sub=user.sub, action=_signoff_action(review_id)
    )
    if not ok:
        with contextlib.suppress(Exception):  # best-effort audit
            await client.record_audit_event(
                audit_type="auth.mfa_nonce_rejected",
                user_id=user.sub,
                classification="confidential",
                payload={
                    "review_id": review_id,
                    "model_id": model_id,
                    "nonce_fingerprint": MfaNonceManager.fingerprint(decision_nonce),
                },
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="mfa_nonce_consumed"
        )

    # 3. Service signs.
    review = await client.sign_model_review(
        review_id, signed_by=user.sub, decision_nonce=decision_nonce
    )

    return templates.TemplateResponse(
        request,
        "model_cards/review_form_partial.html",
        {
            "user": user,
            "card": await client.get_model_card(model_id),
            "review": review,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — model_card
# ─────────────────────────────────────────────────────────────────────────────


async def _model_card_resolver(
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
        card = await c.get_model_card(document_id)

    owner = next(
        (r.name for r in card.responsibles if r.role in ("primary", "business_owner")),
        None,
    ) or "—"
    ctx = {
        "model": {
            "id": card.model_id,
            "name": card.name,
            "family": card.family,
            "version": card.version,
            "framework": card.framework,
            "vendor": card.vendor,
            "intended_use": card.intended_use,
            "prohibited_use": card.prohibited_use,
            "risk_tier": card.risk_tier,
            "responsibles": [r.model_dump(mode="json") for r in card.responsibles],
            "reviews": [r.model_dump(mode="json") for r in card.reviews],
            "next_review_date": card.next_review_date.isoformat() if card.next_review_date else None,
            # Fields the PDF template expects (portal/pdf/templates/model_card.html)
            "provider": card.vendor or "—",
            "owner": owner,
            "last_reviewed_at": card.last_validated_at.isoformat() if card.last_validated_at else "—",
            "status": card.review_status or "active",
        },
        "project": "compliance-portal",
    }
    return (
        "model_card.html",
        ctx,
        f"Model Card {card.model_id} v{card.version}",
        "internal",
    )


def register_model_card_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "model_card" not in reg:
        register_component(
            "model_card",
            template="model_card.html",
            resolver=_model_card_resolver,
            audit_event_type="model_card.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor", "viewer"},
        )


register_model_card_pdf_components()


__all__ = ["router", "register_model_card_pdf_components"]
