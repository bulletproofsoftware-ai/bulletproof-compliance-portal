"""WI-10 — Incident Console router (REQ-CPL-016/017/018).

HTMX UI for managing PRD-18 incident_records. NY DFS Part 500 72-hour
notification countdown, append-only investigation notes (AMD-19 markdown XSS
hardening), affected session linkage, notification status tracking, and
post-incident report generation.

Routes (mounted at /incidents):

    GET  /incidents                            — list page
    GET  /incidents/{inc_id}                   — detail page
    POST /incidents/{inc_id}/notes             — append note
    POST /incidents/{inc_id}/notify            — record notification
    POST /incidents/{inc_id}/transition        — change status
    POST /incidents/{inc_id}/close             — close incident
    POST /incidents/{inc_id}/report            — generate draft report
    POST /incidents/{inc_id}/report/finalize   — promote to evidence package

Plus the Guardian webhook receiver (registered at /webhooks/incidents/terminate
via a separate router so its lifecycle is independent of the user-facing UI):

    POST /webhooks/incidents/terminate         — service-token HMAC + timestamp

AMD-18 — webhook HMAC binds the timestamp into the signed material; the server
rejects timestamps outside ±5 minutes regardless of signature validity.
AMD-19 — investigation notes pass through markdown-it-py html=False + Bleach
allowlist before being persisted/rendered.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from fastapi import APIRouter, Depends, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role, require_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..services.incident_clock import band, format_remaining
from ..services.markdown_render import render_note
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/incidents", tags=["incidents"])
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])

_ALLOWED = (Role.ADMIN, Role.COMPLIANCE_OFFICER)

# Status workflow per WI-10
_VALID_INCIDENT_TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"contained", "closed"},
    "contained": {"closed"},
    "closed": set(),
}


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _csrf_token(request: Request) -> str:
    return request.cookies.get("csrf", "")


# ─────────────────────────────────────────────────────────────────────────────
# AMD-18 — Webhook HMAC verification
# ─────────────────────────────────────────────────────────────────────────────

# Minimum acceptable length for the Guardian webhook shared secret. Matches the
# 32-character floor `portal.config` enforces on `session_secret`. Anything
# shorter (including leftover placeholder values) is treated as unconfigured and
# rejected, because a guessable secret makes a valid signature meaningless.
MIN_WEBHOOK_SECRET_BYTES = 32


def _webhook_secret() -> str:
    """Pull the Guardian webhook secret from settings.

    The secret is shared between PRD-11 Guardian and the compliance portal,
    and it lives on its OWN dedicated settings field —
    `webhook_guardian_secret` — with `WEBHOOK_GUARDIAN_SECRET` as the env
    override. Earlier prototypes reused `signing_key_id` as a placeholder;
    that placeholder has been retired and this function now reads the
    dedicated field directly (PRD-19 audit-2026-05-01 Recommendation 3).

    DEFENSE: returns empty string if not configured — the verification will
    then fail with bad_signature for ALL inputs (fail-closed). The same
    applies to any secret shorter than `MIN_WEBHOOK_SECRET_BYTES`, so a
    leftover placeholder value cannot silently authenticate callers.
    Operators must set `WEBHOOK_GUARDIAN_SECRET` (or `webhook_guardian_secret`
    in settings) to a value of at least 32 characters before exposing this
    endpoint.
    """
    settings = get_settings()
    secret = getattr(settings, "webhook_guardian_secret", None)
    if secret is None:
        # Fall through to environment override or empty (fail-closed).
        import os

        return os.environ.get("WEBHOOK_GUARDIAN_SECRET", "")
    if hasattr(secret, "get_secret_value"):
        return secret.get_secret_value()
    return str(secret)


def verify_guardian_webhook(
    body: bytes,
    *,
    signature_header: str,
    timestamp_header: str,
    secret: str,
    skew_seconds: int = 300,
    now_unix: float | None = None,
) -> None:
    """Validate the AMD-18 HMAC + timestamp scheme. Raises 401 on failure.

    Signed material is `f"{timestamp}." + body` per AMD-18; signature header
    has the form `sha256=<hex>`.

    A structurally valid signature is not sufficient: the shared secret must
    itself meet the minimum strength bar (`MIN_WEBHOOK_SECRET_BYTES`). A short
    or placeholder secret is rejected even when the caller's HMAC is correct,
    because such a secret is guessable and the signature therefore proves
    nothing about the caller's identity. This mirrors the 32-character minimum
    already enforced on `session_secret` in `portal.config`.
    """
    # 1. Timestamp must parse to int.
    try:
        ts = int(timestamp_header)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="bad_timestamp"
        )

    # 2. Skew window
    now = now_unix if now_unix is not None else time.time()
    if abs(now - ts) > skew_seconds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="stale_timestamp"
        )

    # 3. Secret strength. Fail closed on an unset or under-strength secret:
    #    an attacker who can guess the shared secret can mint valid
    #    signatures, so a weak secret is an authentication bypass regardless
    #    of how correct the HMAC computation is.
    if len(secret) < MIN_WEBHOOK_SECRET_BYTES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="bad_signature"
        )

    # 4. HMAC over (timestamp + "." + body)
    signed_material = f"{timestamp_header}.".encode() + body
    # Use hmac.HMAC explicitly (Python 3 idiomatic form) to avoid any
    # ambiguity with `hmac.new()` and to make the cryptographic primitive
    # unambiguous to reviewers. AMD-18 mandates SHA-256.
    expected = (
        "sha256="
        + hmac.HMAC(
            key=secret.encode(),
            msg=signed_material,
            digestmod=hashlib.sha256,
        ).hexdigest()
    )
    # Constant-time comparison to prevent timing side channels.
    if not hmac.compare_digest(expected, signature_header or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="bad_signature"
        )


# ─────────────────────────────────────────────────────────────────────────────
# List + detail
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="incidents_index")
async def incidents_index(
    request: Request,
    severity: str | None = None,
    status_filter: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters: dict[str, Any] = {}
    if severity:
        filters["severity"] = severity
    if status_filter:
        filters["status"] = status_filter
    incidents = await client.list_incidents(**filters)

    decorated = []
    for inc in incidents.items:
        anchor = inc.triggered_at or inc.detected_at
        decorated.append(
            {
                "incident": inc,
                "band": band(anchor),
                "remaining": format_remaining(anchor),
            }
        )
    decorated.sort(
        key=lambda d: (d["band"] == "green", d["band"] == "amber", d["band"] == "red", d["band"] == "overdue")
    )

    kpis = [
        {"label": "Total", "value": len(decorated)},
        {"label": "Open", "value": sum(1 for d in decorated if d["incident"].status != "closed")},
        {"label": "High/critical", "value": sum(1 for d in decorated if d["incident"].severity in ("high", "critical"))},
        {"label": "72h overdue", "value": sum(1 for d in decorated if d["band"] == "overdue")},
    ]
    return templates.TemplateResponse(
        request,
        "incidents/index.html",
        {
            "user": user,
            "rows": decorated,
            "severity_filter": severity,
            "status_filter": status_filter,
            "kpis": kpis,
            "crumbs": [{"label": "Incidents"}],
        },
    )


@router.get("/{inc_id}", response_class=HTMLResponse, name="incident_detail")
async def incident_detail(
    request: Request,
    inc_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    incident = await client.get_incident(inc_id)
    anchor = incident.triggered_at or incident.detected_at
    return templates.TemplateResponse(
        request,
        "incidents/detail.html",
        {
            "user": user,
            "incident": incident,
            "band": band(anchor),
            "remaining": format_remaining(anchor),
            "valid_next_states": sorted(
                _VALID_INCIDENT_TRANSITIONS.get(incident.status, set())
            ),
            "csrf_token": _csrf_token(request),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Notes — AMD-19 markdown hardening applied here
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{inc_id}/notes",
    response_class=HTMLResponse,
    name="incident_add_note",
)
async def incident_add_note(
    request: Request,
    inc_id: str,
    content: str = Form(..., min_length=1, max_length=10_000),
    tags: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Append-only investigation note. Markdown is rendered to HTML on the
    portal (AMD-19) before being shipped to the compliance service so the
    audit chain captures both raw + rendered forms."""
    rendered = render_note(content)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    note = await client.add_incident_note(
        inc_id, content=content, rendered_html=rendered, tags=tag_list
    )

    incident = await client.get_incident(inc_id)
    return templates.TemplateResponse(
        request,
        "incidents/notes_partial.html",
        {"user": user, "incident": incident, "new_note": note},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Notifications
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{inc_id}/notify",
    response_class=HTMLResponse,
    name="incident_add_notification",
)
async def incident_add_notification(
    request: Request,
    inc_id: str,
    recipient: str = Form(..., min_length=1, max_length=200),
    channel: str = Form(...),
    confirmation_id: str = Form(default=""),
    notification_status: str = Form(default="sent"),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    if channel not in {"email", "regulator_portal", "phone", "fax", "in_person"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid channel: {channel}",
        )
    notification = await client.add_incident_notification(
        inc_id,
        recipient=recipient,
        channel=channel,
        confirmation_id=confirmation_id or None,
        status=notification_status,
    )
    incident = await client.get_incident(inc_id)
    return templates.TemplateResponse(
        request,
        "incidents/notify_form_partial.html",
        {"user": user, "incident": incident, "new_notification": notification},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Transition / Close
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{inc_id}/transition",
    response_class=HTMLResponse,
    name="incident_transition",
)
async def incident_transition(
    request: Request,
    inc_id: str,
    to_status: str = Form(...),
    notes: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    incident = await client.get_incident(inc_id)
    valid_next = _VALID_INCIDENT_TRANSITIONS.get(incident.status, set())
    if to_status not in valid_next:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid transition: {incident.status} → {to_status}",
        )
    incident = await client.transition_incident_status(
        inc_id, to_status=to_status, notes=notes or None
    )
    return templates.TemplateResponse(
        request,
        "incidents/timer_partial.html",
        {
            "user": user,
            "incident": incident,
            "band": band(incident.triggered_at or incident.detected_at),
            "remaining": format_remaining(incident.triggered_at or incident.detected_at),
        },
    )


@router.post(
    "/{inc_id}/close",
    response_class=HTMLResponse,
    name="incident_close",
)
async def incident_close(
    request: Request,
    inc_id: str,
    summary: str = Form(default=""),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    incident = await client.close_incident(inc_id, summary=summary or None)
    return templates.TemplateResponse(
        request,
        "incidents/timer_partial.html",
        {
            "user": user,
            "incident": incident,
            "band": "green",
            "remaining": "CLOSED",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Report generation / finalize
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/{inc_id}/report",
    response_class=HTMLResponse,
    name="incident_generate_report",
)
async def incident_generate_report(
    request: Request,
    inc_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    draft = await client.generate_incident_report(inc_id)
    incident = await client.get_incident(inc_id)
    return templates.TemplateResponse(
        request,
        "incidents/notes_partial.html",
        {
            "user": user,
            "incident": incident,
            "report_draft": draft,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Webhook — AMD-18
# ─────────────────────────────────────────────────────────────────────────────


@webhook_router.post(
    "/incidents/terminate",
    name="incident_webhook_terminate",
)
async def incident_webhook_terminate(
    request: Request,
    x_guardian_signature: str = Header(default="", alias="X-Guardian-Signature"),
    x_guardian_timestamp: str = Header(default="", alias="X-Guardian-Timestamp"),
    client: ComplianceClient = Depends(get_compliance_client),
) -> JSONResponse:
    """Guardian TERMINATE webhook — creates an incident from a forensic event.

    AMD-18: HMAC binds timestamp; ±5min skew window enforced before signature
    verification. Signature failure or stale timestamp → 401 + audit emission.
    """
    body = await request.body()
    try:
        verify_guardian_webhook(
            body,
            signature_header=x_guardian_signature,
            timestamp_header=x_guardian_timestamp,
            secret=_webhook_secret(),
        )
    except HTTPException as exc:
        # Audit the rejected attempt; service-account token still attached.
        try:
            await client.record_audit_event(
                audit_type=(
                    "webhook.guardian.stale_timestamp"
                    if exc.detail == "stale_timestamp"
                    else "webhook.guardian.signature_failure"
                ),
                classification="confidential",
                payload={
                    "ip": request.client.host if request.client else "unknown",
                    "ua": request.headers.get("user-agent", ""),
                    "detail": exc.detail,
                },
            )
        except Exception as audit_exc:  # noqa: BLE001
            logger.warning("incident.webhook_audit_failed", error=str(audit_exc))
        raise

    # Parse body
    try:
        import json

        payload = json.loads(body.decode())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"bad_body: {exc}"
        ) from exc

    incident = await client.create_incident(
        title=payload.get("reason", "Guardian TERMINATE"),
        severity=payload.get("severity", "high"),
        triggered_at=payload.get("triggered_at"),
        source="guardian_terminate",
        affected_session_ids=[payload["session_id"]] if payload.get("session_id") else None,
        notes=f"Guardian event_id={payload.get('event_id')}",
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={"incident_id": incident.incident_id},
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — incident_report
# ─────────────────────────────────────────────────────────────────────────────


async def _incident_report_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/incident_report/{inc_id}."""
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
        incident = await c.get_incident(document_id)

    notes = [n.model_dump(mode="json") for n in incident.notes]
    # Build a chronological timeline from notes
    timeline = [
        {"timestamp": n.get("created_at"), "event": n.get("content", "")[:200], "actor": n.get("author_sub") or "—"}
        for n in notes
    ]
    ctx = {
        "incident": {
            "id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "detected_at": incident.detected_at.isoformat(),
            "triggered_at": incident.triggered_at.isoformat() if incident.triggered_at else None,
            "notes": notes,
            "notifications": [n.model_dump(mode="json") for n in incident.notifications],
            "affected_session_ids": incident.affected_session_ids,
            "source": incident.source,
            # Fields the PDF template expects (portal/pdf/templates/incident_report.html)
            "resolved_at": incident.closed_at.isoformat() if incident.closed_at else "—",
            "reporter": incident.source or "—",
            "affected_systems": incident.affected_session_ids or [],
            "summary": incident.title or "—",
            "lessons_learned": notes[-1].get("content") if notes else "—",
            "timeline": timeline,
        },
        "project": "compliance-portal",
    }
    return (
        "incident_report.html",
        ctx,
        f"Incident Report {incident.incident_id}",
        "confidential",
    )


def register_incident_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "incident_report" not in reg:
        register_component(
            "incident_report",
            template="incident_report.html",
            resolver=_incident_report_resolver,
            audit_event_type="incident.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )


register_incident_pdf_components()


__all__ = [
    "router",
    "webhook_router",
    "verify_guardian_webhook",
    "register_incident_pdf_components",
]
