"""WI-07 — Auditor engagement admin router (admin role only).

Implements REQ-CPL-033 (time-boxed accounts, no renewal), REQ-CPL-034
(watermarked downloads, access logging on every view, instant revocation),
and REQ-CPL-035 (minimum-required-scope at engagement boundary).

The portal stores nothing — it calls the compliance service via WI-03.

Routes (mounted at /admin/auditor-engagements, admin only):

    GET  /admin/auditor-engagements                  — list page
    POST /admin/auditor-engagements                  — create new engagement
    GET  /admin/auditor-engagements/{id}             — detail + access log
    POST /admin/auditor-engagements/{id}/revoke      — instant revocation

Compromise containment per REQ-CPL-035: an auditor account holds only the
minimum scope required for the engagement (allowed_artifact_types,
allowed_project_ids). Revocation is instant — no grace period.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.oidc import safe_next_url
from ..auth.rbac import require_role
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..safe_urls import safe_url_segment
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/admin/auditor-engagements", tags=["auditor-admin"])


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _csrf_token_from_cookie(request: Request) -> str:
    return request.cookies.get("csrf", "")


def _parse_iso8601(value: str, *, field: str) -> str:
    """Validate an ISO8601 (or HTML datetime-local) string and return the
    canonical isoformat."""
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field} is required"
        )
    # HTML datetime-local emits "YYYY-MM-DDTHH:MM" — append seconds + Z
    candidates = [value, value + ":00", value + ":00+00:00"]
    for cand in candidates:
        try:
            dt = datetime.fromisoformat(cand.replace("Z", "+00:00"))
            return dt.isoformat()
        except ValueError:
            continue
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field} not ISO8601"
    )


def _split_csv(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="auditor_engagements_index")
async def engagements_index(
    request: Request,
    user: User = Depends(require_role(Role.ADMIN)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    engagements = await client.list_engagements()
    return templates.TemplateResponse(
        request,
        "admin/auditor/index.html",
        {
            "user": user,
            "engagements": engagements,
            "csrf_token": _csrf_token_from_cookie(request),
        },
    )


@router.post("", name="auditor_engagement_create")
async def engagements_create(
    request: Request,
    auditor_email: str = Form(...),
    engagement_start: str = Form(...),
    engagement_end: str = Form(...),
    date_range_start: str = Form(...),
    date_range_end: str = Form(...),
    allowed_artifact_types: str = Form(default=""),
    allowed_project_ids: str = Form(default=""),
    user: User = Depends(require_role(Role.ADMIN)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> RedirectResponse:
    """REQ-CPL-033 — create engagement. End MUST be after start; no renewal —
    new engagement requires new account."""
    start = _parse_iso8601(engagement_start, field="engagement_start")
    end = _parse_iso8601(engagement_end, field="engagement_end")
    if end <= start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="engagement_end must be after engagement_start",
        )
    drs = _parse_iso8601(date_range_start, field="date_range_start")
    dre = _parse_iso8601(date_range_end, field="date_range_end")

    artifact_types = _split_csv(allowed_artifact_types) or [
        "audit_event",
        "evidence_package",
        "gate_decision",
    ]
    project_ids = _split_csv(allowed_project_ids) or None

    engagement = await client.create_engagement(
        auditor_email=auditor_email,
        engagement_start=start,
        engagement_end=end,
        date_range_start=drs,
        date_range_end=dre,
        allowed_artifact_types=artifact_types,
        allowed_project_ids=project_ids,
    )
    return RedirectResponse(
        url=f"/admin/auditor-engagements/{engagement.engagement_id}",
        status_code=303,
    )


@router.get(
    "/{engagement_id}",
    response_class=HTMLResponse,
    name="auditor_engagement_detail",
)
async def engagement_detail(
    request: Request,
    engagement_id: str,
    user: User = Depends(require_role(Role.ADMIN)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    engagement = await client.get_engagement(engagement_id)
    try:
        access_log = await client.get_engagement_access_log(engagement_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "auditor.access_log_fetch_failed",
            engagement_id=engagement_id,
            error=str(exc),
        )
        from shared.api_client import EngagementAccessLog

        access_log = EngagementAccessLog(engagement_id=engagement_id, items=[])

    return templates.TemplateResponse(
        request,
        "admin/auditor/detail.html",
        {
            "user": user,
            "engagement": engagement,
            "access_log": access_log,
            "csrf_token": _csrf_token_from_cookie(request),
        },
    )


@router.post(
    "/{engagement_id}/revoke",
    name="auditor_engagement_revoke",
)
async def engagement_revoke(
    request: Request,
    engagement_id: str,
    reason: str = Form(..., min_length=10),
    user: User = Depends(require_role(Role.ADMIN)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> RedirectResponse:
    """REQ-CPL-034 — instant revocation. No grace period."""
    await client.revoke_engagement(engagement_id, reason=reason)
    try:
        await client.record_audit_event(
            audit_type="auditor.engagement_revoked",
            user_id=user.sub,
            classification="confidential",
            payload={"engagement_id": engagement_id, "reason": reason},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("auditor.revoke_audit_failed", error=str(exc))
    return RedirectResponse(
        url=safe_next_url(
            f"/admin/auditor-engagements/{safe_url_segment(engagement_id)}"
        ),
        status_code=303,
    )


__all__ = ["router"]
