"""WI-06 — Gate Decision Workspace router.

Compliance officers review pending PRD-18 human_gate_decisions, approve/deny/
escalate with mandatory rationale, and receive Ed25519-signed receipts back
from the compliance service. SOX separation-of-duties is enforced both at the
portal pre-check layer (REQ-CPL-010) and authoritatively at the compliance
service. MFA step-up with per-decision nonce binding (AMD-03) protects
confidential and restricted classifications.

Routes (mounted at /gates):

    GET  /gates                         — pending queue page
    GET  /gates/{gate_id}                — decision view (detail + form)
    POST /gates/{gate_id}/decide         — submit decision (CSRF + MFA)
    GET  /gates/{gate_id}/receipt        — re-fetch signed receipt

────────────────────────────────────────────────────────────────────────────
Trust boundary note (AMD-14, CISO M-5)
────────────────────────────────────────────────────────────────────────────

The portal compares `gate.triggered_by` against `current_user.sub` to
disable the decision form when the same identity that fired the gate is
attempting to decide it (REQ-CPL-010 SoD pre-check). The authoritative
SoD check is performed by the compliance service.

BOTH layers depend on the assumption that `gate.triggered_by` accurately
identifies the human or agent that fired the gate event. The portal does
NOT independently verify the value — it is service-attested. The compliance
service / upstream agents own population of `triggered_by`.

Specifically: the portal MUST NOT have any code path that lets the portal
SET `triggered_by` on a gate. Lint check (CI) confirms the field is never
written by the portal in any HTTP request body.

If this assumption is violated upstream, the SoD enforcement collapses.
This is a known trust boundary, accepted in the architecture as long as
PRD-18 documents and audits the `triggered_by` ingress path.

────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.mfa import MfaNonceManager, StepUpRequired, require_mfa
from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/gates", tags=["gates"])

_ALLOWED = (Role.ADMIN, Role.COMPLIANCE_OFFICER)

# Classifications that require MFA step-up per AMD-03 (max age 60s)
_MFA_REQUIRED_CLASSIFICATIONS = frozenset({"confidential", "restricted"})


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _get_nonce_manager(request: Request) -> MfaNonceManager:
    """Singleton-per-app MFA nonce manager.

    Created lazily on first access (so tests that build a minimal app don't
    have to install one explicitly). The 60-second TTL matches AMD-03.
    """
    mgr = getattr(request.app.state, "mfa_nonce_manager", None)
    if mgr is None:
        mgr = MfaNonceManager(max_age_s=60)
        request.app.state.mfa_nonce_manager = mgr
    return mgr


def _decision_action(gate_id: str) -> str:
    """Stable string used as the MFA-nonce action binding (AMD-03)."""
    return f"gate.decide:{gate_id}"


def _csrf_token_from_cookie(request: Request) -> str:
    return request.cookies.get("csrf", "")


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="gates_index")
async def gates_index(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    gates = await client.list_human_gates(status="pending")
    # Also fetch recent decided gates so the page surfaces historical activity
    decided = await client.list_human_gates(status="decided")
    now = datetime.now(UTC)
    sla_remaining_seconds: dict[str, float] = {}
    sla_remaining_text: dict[str, str] = {}
    for g in gates.items:
        if g.sla_deadline:
            delta = (g.sla_deadline - now).total_seconds()
            sla_remaining_seconds[g.gate_id] = delta
            sla_remaining_text[g.gate_id] = (
                f"{int(delta // 3600)}h {int((delta % 3600) // 60)}m"
                if delta > 0
                else "OVERDUE"
            )
        else:
            sla_remaining_seconds[g.gate_id] = None  # type: ignore[assignment]
            sla_remaining_text[g.gate_id] = "—"
    overdue = sum(1 for s in sla_remaining_seconds.values() if s is not None and s <= 0)
    kpis = [
        {"label": "Pending", "value": len(gates.items)},
        {"label": "Recently decided", "value": len(decided.items)},
        {"label": "SLA overdue", "value": overdue},
    ]
    return templates.TemplateResponse(
        request,
        "gates/index.html",
        {
            "user": user,
            "gates": gates,
            "decided_gates": decided,
            "sla_remaining_seconds": sla_remaining_seconds,
            "sla_remaining_text": sla_remaining_text,
            "kpis": kpis,
            "crumbs": [{"label": "Gates"}],
        },
    )


@router.get(
    "/{gate_id}",
    response_class=HTMLResponse,
    name="gate_detail",
)
async def gate_detail(
    request: Request,
    gate_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    gate = await client.get_human_gate(gate_id)

    # AMD-14 / REQ-CPL-010 SoD pre-check (defense-in-depth)
    sod_violation = bool(gate.triggered_by) and gate.triggered_by == user.sub

    # AMD-03 — issue a per-decision nonce on detail-page render for
    # confidential/restricted gates. The form embeds it as a hidden field.
    decision_nonce: str | None = None
    requires_mfa_step_up = (gate.classification or "").lower() in _MFA_REQUIRED_CLASSIFICATIONS
    if requires_mfa_step_up and not sod_violation:
        nonce_mgr = _get_nonce_manager(request)
        decision_nonce = nonce_mgr.issue(
            user_sub=user.sub, action=_decision_action(gate_id)
        )

    return templates.TemplateResponse(
        request,
        "gates/gate_detail.html",
        {
            "user": user,
            "gate": gate,
            "sod_violation": sod_violation,
            "decision_nonce": decision_nonce,
            "requires_mfa": requires_mfa_step_up,
            "csrf_token": _csrf_token_from_cookie(request),
        },
    )


@router.post(
    "/{gate_id}/decide",
    response_class=HTMLResponse,
    name="gate_decide",
)
async def gate_decide(
    request: Request,
    gate_id: str,
    decision: str = Form(...),
    rationale: str = Form(..., min_length=20),
    decision_nonce: str = Form(default=""),
    escalate_to_role: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Submit a decision on a gate.

    Order of enforcement:
      1. Decision value validation
      2. Escalation target validation
      3. Fetch gate to obtain triggered_by + classification
      4. SoD pre-check (REQ-CPL-010): triggered_by != user.sub
      5. AMD-03: for confidential/restricted, require fresh MFA AND consume a
         valid `decision_nonce` bound to (user.sub, gate_id)
      6. Submit to compliance service (authoritative SoD + signing)
      7. Render signed receipt
    """
    if decision not in {"approve", "deny", "escalate"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid decision value: {decision!r}",
        )
    if decision == "escalate" and not escalate_to_role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="escalate_to_role is required when decision=escalate",
        )

    gate = await client.get_human_gate(gate_id)

    # SoD pre-check (REQ-CPL-010)
    if gate.triggered_by and gate.triggered_by == user.sub:
        try:
            await client.record_audit_event(
                audit_type="gate.decision.sod_blocked",
                user_id=user.sub,
                classification="confidential",
                payload={
                    "gate_id": gate_id,
                    "triggered_by": gate.triggered_by,
                    "reason": "sod_pre_check",
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("gate.sod_audit_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SOX separation of duties: cannot decide on a gate you triggered",
        )

    # AMD-03 — MFA per-decision binding
    classification = (gate.classification or "").lower()
    if classification in _MFA_REQUIRED_CLASSIFICATIONS:
        # Step-up freshness — 60s window per AMD-03
        mfa_dep = require_mfa(max_age_s=60)
        try:
            await mfa_dep(user=user)  # type: ignore[arg-type]
        except StepUpRequired:
            raise

        # Consume the decision_nonce bound to this user + gate
        if not decision_nonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="decision_nonce is required for this gate's classification",
            )
        nonce_mgr = _get_nonce_manager(request)
        ok = nonce_mgr.consume(
            decision_nonce, user_sub=user.sub, action=_decision_action(gate_id)
        )
        if not ok:
            # The nonce was either: never issued, expired (>60s), bound to a
            # different user/gate, or already consumed (replay).
            try:
                await client.record_audit_event(
                    audit_type="auth.mfa_nonce_rejected",
                    user_id=user.sub,
                    classification="confidential",
                    payload={
                        "gate_id": gate_id,
                        "nonce_fingerprint": MfaNonceManager.fingerprint(
                            decision_nonce
                        ),
                    },
                )
            except Exception:  # noqa: BLE001
                pass
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="mfa_nonce_invalid_or_expired",
            )

    # Submit decision (compliance service is authoritative for SoD + signing)
    receipt = await client.decide_human_gate(
        gate_id,
        decision=decision,
        rationale=rationale,
        decision_nonce=decision_nonce or None,
        escalate_to_role=escalate_to_role or None,
    )

    # Audit the decision client-side too — duplicate is fine; service is
    # authoritative, this is a portal-side breadcrumb for forensics.
    try:
        await client.record_audit_event(
            audit_type="gate.decision.submitted_via_portal",
            user_id=user.sub,
            classification="confidential",
            payload={
                "gate_id": gate_id,
                "decision": decision,
                "receipt_id": receipt.receipt_id,
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("gate.decision_audit_failed", error=str(exc))

    return templates.TemplateResponse(
        request,
        "gates/receipt.html",
        {"user": user, "receipt": receipt},
    )


@router.get(
    "/{gate_id}/receipt",
    response_class=HTMLResponse,
    name="gate_receipt",
)
async def gate_receipt(
    request: Request,
    gate_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    receipt = await client.get_gate_receipt(gate_id)
    return templates.TemplateResponse(
        request,
        "gates/receipt.html",
        {"user": user, "receipt": receipt},
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver (REQ-CPL-011 — signed decision receipts as PDF)
# ─────────────────────────────────────────────────────────────────────────────


async def _gate_decision_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/gate_decision/{gate_id}."""
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
        receipt = await c.get_gate_receipt(document_id)
        gate = await c.get_human_gate(document_id)

    ctx = {
        "decision": {
            "id": receipt.receipt_id,
            "gate_id": receipt.gate_id,
            "decision": receipt.decision,
            "rationale": receipt.rationale,
            "decided_by": receipt.decided_by,
            "decided_at": receipt.decided_at.isoformat()
            if receipt.decided_at
            else "—",
            "classification": gate.classification or "confidential",
            "triggered_by": gate.triggered_by,
            "evidence_snapshot": receipt.evidence_snapshot,
            "signature": receipt.signature,
            "signing_key_id": receipt.signing_key_id,
        },
        # `gate` shape for portal/pdf/templates/gate_decision.html
        "gate": {
            "id": receipt.gate_id,
            "gate_type": gate.title or "human_gate",
            "project_id": "compliance-portal",
            "status": gate.status or "decided",
            "decision": receipt.decision,
            "decided_by": receipt.decided_by,
            "decided_at": receipt.decided_at.isoformat() if receipt.decided_at else "—",
            "mfa_at": "—",
            "hash": receipt.signature or "—",
            "rationale": receipt.rationale or "—",
            "inputs": list(receipt.evidence_snapshot or []),
        },
        "project": "compliance-portal",
    }
    return (
        "gate_decision.html",
        ctx,
        f"Gate Decision Receipt {receipt.receipt_id}",
        gate.classification or "confidential",
    )


def register_gate_pdf_components() -> None:
    """Register gate_decision on the default registry. Idempotent."""
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "gate_decision" not in reg:
        register_component(
            "gate_decision",
            template="gate_decision.html",
            resolver=_gate_decision_resolver,
            audit_event_type="gate.decision.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )


register_gate_pdf_components()


__all__ = ["router", "register_gate_pdf_components"]
