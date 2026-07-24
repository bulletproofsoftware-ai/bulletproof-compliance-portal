"""WI-04 — Audit Explorer router.

Read-only HTMX UI rendering PRD-18 immutable_audit_events through the
WI-03 ComplianceClient. The portal NEVER writes to the audit chain — every
export action is itself audited via `record_audit_event` (REQ-CPL-039).

CISO amendment AMD-07 (Repudiation / OWASP A08, Client-Side Hash
Recomputation) is implemented in the verify_partial template + the
/audit/verify/{event_id} endpoint:

    - Service verdict comes from compliance service `verify_hash_chain`.
    - Client recomputes SHA-256 in-browser over canonical payload+prev_hash.
    - If verdicts disagree, a red INTEGRITY ALERT banner is displayed.

This defends against a compromised compliance service that returns PASS for
a tampered chain.

Routes (mounted at /audit):

    GET /audit                         — full page (filters + result list)
    GET /audit/events                  — HTMX partial: paginated event list
    GET /audit/events/{event_id}       — HTMX partial: single event detail
    GET /audit/sessions/{session_id}   — HTMX partial: session timeline
    GET /audit/verify/{event_id}       — HTMX partial: verify panel (AMD-07)
    GET /audit/export.jsonl            — JSONL streaming export

All routes require admin, compliance_officer, or auditor role; auditor scope is
auto-merged into upstream queries by the WI-03 client.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/audit", tags=["audit"])

# Roles that can read the audit explorer. Auditor scope is enforced upstream.
_ALLOWED = (Role.ADMIN, Role.COMPLIANCE_OFFICER, Role.AUDITOR)


def _templates_dep() -> Jinja2Templates:
    return get_templates()


# ─────────────────────────────────────────────────────────────────────────────
# Filter parsing — used by /audit, /audit/events, /audit/export.jsonl
# ─────────────────────────────────────────────────────────────────────────────


def _parse_filters(
    *,
    from_: str | None,
    to: str | None,
    user_id: str | None,
    session_id: str | None,
    event_type: str | None,
    classification: str | None,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    """Translate HTML form params → ComplianceClient kwargs.

    Empty strings are dropped so the upstream service applies its defaults.
    """
    filters: dict[str, Any] = {}
    if from_:
        filters["from"] = from_
    if to:
        filters["to"] = to
    if user_id:
        filters["user_id"] = user_id
    if session_id:
        filters["session_id"] = session_id
    if event_type:
        filters["event_type"] = event_type
    if classification:
        filters["classification"] = classification
    if cursor:
        filters["cursor"] = cursor
    filters["limit"] = limit
    return filters


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="audit_index")
async def audit_index(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """Full page — filter form + live HTMX-loaded results panel."""
    return templates.TemplateResponse(
        request,
        "audit/index.html",
        {"user": user, "crumbs": [{"label": "Audit"}]},
    )


@router.get("/events", response_class=HTMLResponse, name="audit_events_partial")
async def audit_events_partial(
    request: Request,
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    filters = _parse_filters(
        from_=from_,
        to=to,
        user_id=user_id,
        session_id=session_id,
        event_type=event_type,
        classification=classification,
        cursor=cursor,
        limit=limit,
    )
    events = await client.list_audit_events(**filters)
    return templates.TemplateResponse(
        request,
        "audit/events_partial.html",
        {"user": user, "events": events},
    )


@router.get(
    "/events/{event_id}",
    response_class=HTMLResponse,
    name="audit_event_detail_partial",
)
async def audit_event_detail_partial(
    request: Request,
    event_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    event = await client.get_audit_event(event_id)
    return templates.TemplateResponse(
        request,
        "audit/event_detail_partial.html",
        {"user": user, "event": event},
    )


@router.get(
    "/sessions/{session_id}",
    response_class=HTMLResponse,
    name="audit_session_timeline_partial",
)
async def audit_session_timeline_partial(
    request: Request,
    session_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-006 — chronological reconstruction of all events for one session."""
    events = await client.list_audit_events(session_id=session_id, limit=200)
    return templates.TemplateResponse(
        request,
        "audit/session_timeline_partial.html",
        {"user": user, "session_id": session_id, "events": events},
    )


@router.get(
    "/verify/{event_id}",
    response_class=HTMLResponse,
    name="audit_verify_partial",
)
async def audit_verify_partial(
    request: Request,
    event_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """AMD-07 — hash-chain verification panel.

    Returns a partial that includes:
      * service-side verdict (from `verify_hash_chain`)
      * the canonical payload + prev_hash for the requested event so the
        browser can recompute SHA-256 client-side and compare against
        `event.chain_hash`.

    Banner logic in the template highlights MISMATCH between service and
    client recomputation.
    """
    event = await client.get_audit_event(event_id)

    # Events reconstructed from external sources (e.g. the governance audit DB)
    # are NOT part of the portal's hash chain — they carry no chain_hash. There
    # is nothing to recompute client-side, so verification is N/A. Running it
    # anyway would compare a recomputed SHA-256 against a null expected hash
    # (always MISMATCH) while the service trivially PASSes a zero-length range,
    # raising a FALSE integrity alert.
    chained = event.chain_hash is not None
    service_pass: bool | None = None
    verify_payload: dict[str, Any] | None = None
    if chained:
        # Range used for the service verdict — verify the chain segment ending
        # at this event.
        chain_idx = event.chain_index or 0
        from_idx = max(0, chain_idx - 4)
        verification = await client.verify_hash_chain(from_id=from_idx, to_id=chain_idx)
        service_pass = bool(verification.ok)
        # Canonical bytes for client-side recomputation.
        verify_payload = {
            "payload": event.payload,
            "prev_hash": event.prev_hash,
            "expected_hash": event.chain_hash,
        }
    return templates.TemplateResponse(
        request,
        "audit/verify_partial.html",
        {
            "user": user,
            "event": event,
            "chained": chained,
            "service_pass": service_pass,
            "verify_payload": verify_payload,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSONL export
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/export.jsonl", name="audit_export_jsonl")
async def audit_export_jsonl(
    request: Request,
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    page_size: int = Query(default=200, ge=1, le=1000),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> StreamingResponse:
    """REQ-CPL-006 — line-delimited JSON export of the filtered result set.

    The export is itself audited (initiated / completed / aborted) via
    `record_audit_event`. For auditor users, the first line is a non-chain
    metadata watermark identifying the engagement.
    """

    base_filters = _parse_filters(
        from_=from_,
        to=to,
        user_id=user_id,
        session_id=session_id,
        event_type=event_type,
        classification=classification,
        cursor=None,
        limit=page_size,
    )

    # Emit "initiated" event before the first byte
    try:
        await client.record_audit_event(
            audit_type="audit.export.initiated",
            user_id=user.sub,
            classification="internal",
            payload={"filters": base_filters, "format": "jsonl"},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit.export.initiated_audit_failed", error=str(exc))

    async def _stream() -> AsyncIterator[bytes]:
        rows = 0
        try:
            # Auditor watermark line (NOT part of audit chain — descriptive only)
            if user.has_role(Role.AUDITOR) and user.auditor_scope is not None:
                meta = {
                    "_export_meta": {
                        "auditor": user.sub,
                        "engagement_id": user.auditor_scope.engagement_id,
                        "exported_at": datetime.now(UTC).isoformat(),
                        "filters": base_filters,
                    }
                }
                yield (json.dumps(meta, separators=(",", ":")) + "\n").encode("utf-8")

            cursor: str | None = None
            while True:
                page_filters = dict(base_filters)
                if cursor:
                    page_filters["cursor"] = cursor
                page = await client.list_audit_events(**page_filters)
                for ev in page.items:
                    line = ev.model_dump(mode="json")
                    yield (
                        json.dumps(line, separators=(",", ":"), default=str) + "\n"
                    ).encode("utf-8")
                    rows += 1
                if not page.next_cursor:
                    break
                cursor = page.next_cursor

            # Completed event
            try:
                await client.record_audit_event(
                    audit_type="audit.export.completed",
                    user_id=user.sub,
                    classification="internal",
                    payload={"row_count": rows, "filters": base_filters},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "audit.export.completed_audit_failed", error=str(exc)
                )
        except Exception as exc:  # noqa: BLE001
            try:
                await client.record_audit_event(
                    audit_type="audit.export.aborted",
                    user_id=user.sub,
                    classification="internal",
                    payload={
                        "rows_written": rows,
                        "error": str(exc)[:500],
                        "filters": base_filters,
                    },
                )
            except Exception:  # noqa: BLE001
                pass
            raise

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = f"audit-export-{timestamp}.jsonl"
    return StreamingResponse(
        _stream(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=0, no-store",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolvers (REQ-CPL-045) — registered at module import time so any app
# that imports this router automatically picks them up.
# ─────────────────────────────────────────────────────────────────────────────


async def _audit_event_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/audit_event/{event_id}."""
    from ..dependencies import get_compliance_client as _make_client  # noqa: E402

    # Resolvers don't have the request scope FastAPI dependency machinery, so
    # we construct a per-call client. This mirrors how dependencies.py would
    # build it — but without a request id (the user sub still flows through).
    from shared.api_client import ComplianceClient as _Client  # noqa: F401
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
        event = await c.get_audit_event(document_id)

    ctx = {
        "event": {
            "id": event.event_id,
            "audit_type": event.audit_type,
            "user_id": event.user_id,
            "classification": event.classification,
            "ts": event.ts.isoformat() if event.ts else "—",
            "hash": event.chain_hash,
            "prev_hash": event.prev_hash,
            "payload": event.payload,
        },
        "project": "compliance-portal",
    }
    return ("audit_event.html", ctx, f"Audit Event {event.event_id}",
            event.classification or "internal")


async def _session_timeline_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/session_timeline/{session_id}.

    Reuses the `audit_event.html` template — PRD-19 doesn't ship a dedicated
    timeline PDF template in this batch (could be added later). The context is
    a synthetic event whose payload includes all session events.
    """
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
        page = await c.list_audit_events(session_id=document_id, limit=500)

    serialized = [ev.model_dump(mode="json") for ev in page.items]
    ctx = {
        "event": {
            "id": f"timeline-{document_id}",
            "audit_type": "session.timeline",
            "user_id": user.sub,
            "classification": "internal",
            "ts": datetime.now(UTC).isoformat(),
            "hash": "—",
            "prev_hash": "—",
            "payload": {"session_id": document_id, "events": serialized},
        },
        "project": "compliance-portal",
    }
    return ("audit_event.html", ctx, f"Session Timeline {document_id}", "internal")


def register_audit_pdf_components() -> None:
    """Register both audit PDF components on the default registry.

    Idempotent — safe to call once at app startup. If already registered (e.g.
    in tests that mount the router multiple times), the duplicate is silently
    swallowed.
    """
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "audit_event" not in reg:
        register_component(
            "audit_event",
            template="audit_event.html",
            resolver=_audit_event_resolver,
            audit_event_type="audit.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )
    if "session_timeline" not in reg:
        register_component(
            "session_timeline",
            template="audit_event.html",
            resolver=_session_timeline_resolver,
            audit_event_type="audit.session_timeline.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )


# Register on import. main.py will also call this defensively if it wants to
# manage the order explicitly. Idempotent.
register_audit_pdf_components()


__all__ = ["router", "register_audit_pdf_components"]
