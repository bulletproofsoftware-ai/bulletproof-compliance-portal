"""PDF export router — `/export/pdf/{component}/{document_id}`.

Generic dispatcher that:

  1. Looks up the component spec in the PdfComponentRegistry
  2. Calls the spec's resolver(document_id, current_user) which:
        - Loads the underlying domain object via the compliance client
        - Enforces RBAC at render time (raises 403 on auditor scope misses)
        - Returns (template_name, jinja_context, document_title, classification)
  3. For auditor users: builds a WatermarkSpec from current_user.auditor_scope
        - Auditors WITHOUT an auditor_scope are rejected (403)
  4. Renders via PdfService.pdf_export
  5. Records the audit event (PdfService also emits its internal event; the
     router records the higher-level "user-facing download" event to clarify
     intent in the audit chain)
  6. Returns the PDF as a 200 with Content-Disposition: attachment
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response

from ..auth.models import Role, User
from ..auth.rbac import current_user
from ..logging import get_logger
from ..pdf.audit import PdfAuditEvent, emit_pdf_audit_event
from ..pdf.registry import PdfComponentRegistry, get_default_registry
from ..pdf.service import PdfRenderError, PdfService, get_pdf_service
from ..pdf.watermark import WatermarkSpec

logger = get_logger(__name__)

router = APIRouter(prefix="/export", tags=["export"])


def _safe_filename(component: str, document_id: str) -> str:
    """Produce a Content-Disposition filename. Normalize unsafe chars."""
    safe_doc = "".join(c if c.isalnum() or c in "-_." else "_" for c in document_id)
    safe_comp = "".join(c if c.isalnum() or c in "-_" else "_" for c in component)
    return f"{safe_comp}-{safe_doc}.pdf"


def _build_auditor_watermark(user: User) -> WatermarkSpec:
    if user.auditor_scope is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="auditor scope is required for PDF export",
        )
    scope = user.auditor_scope
    summary_parts: list[str] = []
    if scope.allowed_artifact_types:
        summary_parts.append(
            "artifacts: " + ",".join(scope.allowed_artifact_types[:6])
        )
    if scope.allowed_project_ids is not None:
        summary_parts.append(
            f"projects: {','.join(scope.allowed_project_ids[:4])}"
            if scope.allowed_project_ids
            else "projects: none"
        )
    return WatermarkSpec(
        auditor_sub=user.sub,
        engagement_id=scope.engagement_id,
        timestamp=datetime.now(UTC),
        scope_summary="; ".join(summary_parts) if summary_parts else None,
        expires_at=scope.engagement_end,
    )


def _get_pdf_service_dep(request: Request) -> PdfService:
    """Use app.state.pdf_service if main.py wired one; else fall back."""
    svc = getattr(request.app.state, "pdf_service", None)
    if svc is None:
        svc = get_pdf_service()
    return svc


def _get_registry_dep(request: Request) -> PdfComponentRegistry:
    reg = getattr(request.app.state, "pdf_registry", None)
    if reg is None:
        reg = get_default_registry()
    return reg


@router.get(
    "/pdf/{component}/{document_id:path}",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}},
        403: {"description": "Forbidden — role or scope check failed"},
        404: {"description": "Unknown component or document"},
        504: {"description": "PDF render timeout"},
    },
)
async def export_pdf(
    component: str,
    document_id: str,
    request: Request,
    user: User = Depends(current_user),
    pdf_service: PdfService = Depends(_get_pdf_service_dep),
    registry: PdfComponentRegistry = Depends(_get_registry_dep),
) -> Response:
    spec = registry.get(component)
    if spec is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"unknown PDF export component: {component!r}",
        )

    # ── Role gate ──────────────────────────────────────────────────────────
    user_role_value = user.roles[0].value if user.roles else "viewer"
    if not any(spec.is_role_allowed(r.value) for r in user.roles):
        # Audit the denial
        await emit_pdf_audit_event(
            getattr(request.app.state, "compliance_client", None),
            PdfAuditEvent(
                audit_type="pdf.export.denied",
                component=component,
                document_id=document_id,
                user_sub=user.sub,
                user_role=user_role_value,
                title="(denied)",
                block_reason=f"role {user_role_value!r} not in allowed_roles {sorted(spec.allowed_roles)}",
            ),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role {user_role_value!r} not permitted for component {component!r}",
        )

    # Auditor-only components reject viewer/sme even if listed in allowed_roles
    # (defense in depth)
    if spec.auditor_only_components and not user.has_role(Role.AUDITOR):
        # Allow admins and compliance_officers to still pull these (oversight)
        if not user.has_any_role(Role.ADMIN, Role.COMPLIANCE_OFFICER):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"component {component!r} reserved for auditor role",
            )

    # ── Resolver — RBAC + data load ────────────────────────────────────────
    from shared.api_client.exceptions import NotFoundError as _ClientNotFound
    try:
        template, context, title, classification = await spec.resolver(document_id, user)
    except HTTPException:
        raise
    except _ClientNotFound as exc:
        logger.info(
            "pdf.export.not_found",
            component=component,
            document_id=document_id,
            user_id=user.sub,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{component} {document_id!r} not found",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "pdf.export.resolver_failed",
            component=component,
            document_id=document_id,
            user_id=user.sub,
            error=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"resolver for component {component!r} failed",
        ) from exc

    # ── Watermark for auditors ─────────────────────────────────────────────
    watermark: WatermarkSpec | None = None
    if user.has_role(Role.AUDITOR):
        watermark = _build_auditor_watermark(user)

    # ── Signature extraction (component-specific) ──────────────────────────
    signature = spec.extract_signature(context)
    require_pades = spec.requires_pades(context)

    # ── Render ─────────────────────────────────────────────────────────────
    try:
        pdf_bytes = await pdf_service.pdf_export(
            template=template,
            context=context,
            title=title,
            user_identity=user.sub,
            user_role=user_role_value,
            project=context.get("project"),
            watermark=watermark,
            signature=signature,
            require_pades=require_pades,
            document_id=document_id,
            component=component,
            version_or_etag=context.get("etag"),
            classification=classification,
        )
    except PdfRenderError as exc:
        if exc.blocked_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"PDF render rejected unsafe asset reference: {exc.blocked_url}",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=str(exc),
        ) from exc

    # ── User-facing audit event ────────────────────────────────────────────
    await emit_pdf_audit_event(
        getattr(request.app.state, "compliance_client", None),
        PdfAuditEvent(
            audit_type=spec.audit_event_type,
            component=component,
            document_id=document_id,
            user_sub=user.sub,
            user_role=user_role_value,
            title=title,
            classification=classification,
            watermarked=watermark is not None,
            signed=signature is not None,
            pades_signed=require_pades,
            file_size=len(pdf_bytes),
            watermark_id=watermark.watermark_id if watermark else None,
        ),
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_filename(component, document_id)}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=0, no-store",
        },
    )


@router.get("/pdf", include_in_schema=False)
async def list_components(
    user: User = Depends(current_user),
    registry: PdfComponentRegistry = Depends(_get_registry_dep),
) -> dict[str, list[str]]:
    """Internal helper — list registered components for a user."""
    visible = [
        c
        for c in registry.list_components()
        if (spec := registry.get(c)) is not None
        and any(spec.is_role_allowed(r.value) for r in user.roles)
    ]
    return {"components": visible}


__all__ = ["router"]
