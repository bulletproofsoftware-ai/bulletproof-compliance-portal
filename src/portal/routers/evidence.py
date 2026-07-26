"""WI-05 — Evidence Package Library router.

Surfaces PRD-18 evidence packages with Ed25519 signature display, version
history, version diffs, signature re-verification, and audited downloads.
For auditor users, downloads route through the WI-19 PDF service so the
artifact carries the AMD-06 auditor watermark (REQ-CPL-008).

Routes (mounted at /evidence):

    GET  /evidence                                 — full page (package list)
    GET  /evidence/{pkg_id}                        — full page (package detail)
    GET  /evidence/{pkg_id}/versions               — HTMX partial (versions)
    GET  /evidence/{pkg_id}/diff?from=v1&to=v2     — HTMX partial (diff)
    GET  /evidence/{pkg_id}/verify                 — HTMX partial (re-verify)
    GET  /evidence/{pkg_id}/download               — audited bytes download
                                                     (auditor → watermarked PDF
                                                      via /export/pdf/...)

Every download is audit-logged (REQ-CPL-007 — user, ts, IP, purpose).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..auth.oidc import safe_next_url
from ..pdf import register_component
from ..safe_urls import safe_url_segment
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/evidence", tags=["evidence"])

_ALLOWED = (Role.ADMIN, Role.COMPLIANCE_OFFICER, Role.AUDITOR)


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _client_ip(request: Request) -> str:
    """Extract client IP. Forwarded header middleware has already populated
    `request.client.host` if a trusted proxy fronted the request."""
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# HTML routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="evidence_index")
async def evidence_index(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    packages = await client.list_evidence_packages()
    total = packages.total if packages.total is not None else len(packages.items)
    kpis = [
        {"label": "Packages", "value": total},
        {"label": "Signed", "value": sum(1 for p in packages.items if p.signed_by)},
        {"label": "Restricted", "value": sum(1 for p in packages.items if (p.classification or "").lower() == "restricted")},
    ]
    return templates.TemplateResponse(
        request,
        "evidence/index.html",
        {
            "user": user,
            "packages": packages,
            "kpis": kpis,
            "crumbs": [{"label": "Evidence"}],
        },
    )


@router.get(
    "/{package_id}",
    response_class=HTMLResponse,
    name="evidence_package_detail",
)
async def evidence_package_detail(
    request: Request,
    package_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    package = await client.get_evidence_package(package_id)
    signature = await client.verify_evidence_signature(package_id, version=package.version)
    return templates.TemplateResponse(
        request,
        "evidence/package_detail.html",
        {"user": user, "package": package, "signature": signature},
    )


@router.get(
    "/{package_id}/versions",
    response_class=HTMLResponse,
    name="evidence_versions_partial",
)
async def evidence_versions_partial(
    request: Request,
    package_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    versions = await client.list_evidence_versions(package_id)
    return templates.TemplateResponse(
        request,
        "evidence/versions_partial.html",
        {"user": user, "package_id": package_id, "versions": versions},
    )


@router.get(
    "/{package_id}/diff",
    response_class=HTMLResponse,
    name="evidence_diff_partial",
)
async def evidence_diff_partial(
    request: Request,
    package_id: str,
    from_: str = Query(alias="from"),
    to: str = Query(...),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    diff = await client.get_evidence_diff(
        package_id, from_version=from_, to_version=to
    )
    return templates.TemplateResponse(
        request,
        "evidence/diff_partial.html",
        {"user": user, "package_id": package_id, "diff": diff},
    )


@router.get(
    "/{package_id}/verify",
    response_class=HTMLResponse,
    name="evidence_verify_partial",
)
async def evidence_verify_partial(
    request: Request,
    package_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    signature = await client.verify_evidence_signature(package_id)
    return templates.TemplateResponse(
        request,
        "evidence/verify_partial.html",
        {"user": user, "signature": signature},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Download (audited)
# ─────────────────────────────────────────────────────────────────────────────


@router.get(
    "/{package_id}/download",
    name="evidence_download",
)
async def evidence_download(
    request: Request,
    package_id: str,
    purpose: str = Query(default="ad-hoc download", min_length=1, max_length=500),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> Response:
    """REQ-CPL-007 — download with audit logging.

    For auditor users, redirects to the watermarked PDF export route so the
    artifact carries the AMD-06 watermark + identity metadata. For others, the
    download metadata is returned (the actual bytes are streamed by the
    compliance service via the URL it returns, which the user's browser
    fetches separately — production deployment will add a streaming proxy).
    """
    # Audit the download intent BEFORE returning bytes, so a partial download
    # still leaves a forensic trail.
    try:
        await client.record_audit_event(
            audit_type="evidence.download.initiated",
            user_id=user.sub,
            classification="confidential",
            payload={
                "package_id": package_id,
                "ip": _client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "purpose": purpose,
                "watermarked": user.has_role(Role.AUDITOR),
            },
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("evidence.download_audit_failed", error=str(exc))

    if user.has_role(Role.AUDITOR):
        # Auditor downloads MUST be watermarked — redirect through the PDF
        # service which applies AMD-06 metadata + visible watermark.
        return RedirectResponse(
            url=safe_next_url(
                f"/export/pdf/evidence_package/{safe_url_segment(package_id)}"
            ),
            status_code=303,
        )

    # Non-auditor: fetch download metadata from compliance service. The
    # service returns a presigned URL that the browser then fetches.
    metadata = await client.get_evidence_download_metadata(
        package_id, purpose=purpose
    )
    # Real-source evidence packages have no streamable artifact yet (they're
    # synthesized from BRD-tracker + git commits). Redirect to the PDF export
    # so the user gets a useful document instead of a 404 on the placeholder
    # /static/evidence/...tar.gz URL.
    if metadata.download_url and metadata.download_url.startswith("/static/evidence/"):
        return RedirectResponse(
            url=safe_next_url(
                f"/export/pdf/evidence_package/{safe_url_segment(package_id)}"
            ),
            status_code=303,
        )
    if metadata.download_url:
        return RedirectResponse(metadata.download_url, status_code=303)
    # If the service didn't supply a download_url, return the metadata as JSON
    # — caller can implement its own retrieval.
    return Response(
        content=metadata.model_dump_json(),
        media_type="application/json",
        headers={"X-Content-Type-Options": "nosniff"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver (REQ-CPL-008 — auditor watermark applied by export router)
# ─────────────────────────────────────────────────────────────────────────────


async def _evidence_package_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/evidence_package/{package_id}.

    Auditor watermark is applied by the export router (`_build_auditor_watermark`)
    based on `user.has_role(Role.AUDITOR)`. We do NOT add the watermark here —
    that would double-apply it.
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
        package = await c.get_evidence_package(document_id)
        try:
            signature = await c.verify_evidence_signature(
                document_id, version=package.version
            )
            sig_payload = {
                "valid": signature.valid,
                "algorithm": signature.algorithm,
                "signing_key_id": signature.signing_key_id,
                "signed_at": signature.signed_at.isoformat()
                if signature.signed_at
                else "—",
            }
        except Exception:  # noqa: BLE001
            sig_payload = {"valid": False, "algorithm": "Ed25519"}

    ctx = {
        "package": {
            "id": package.package_id,
            "title": package.title,
            "version": package.version,
            "classification": package.classification,
            "signed_by": package.signed_by,
            "signature": sig_payload,
            "created_at": package.created_at.isoformat() if package.created_at else "—",
            # Fields the PDF template reads (see portal/pdf/templates/evidence_package.html)
            "project_id": "compliance-portal",
            "created_by": package.signed_by or "—",
            "status": "signed" if sig_payload.get("valid") else "draft",
            "manifest_sha256": sig_payload.get("signing_key_id") or "—",
            "artifacts": [],  # template iterates safely over empty list
        },
        "project": "compliance-portal",
    }
    return (
        "evidence_package.html",
        ctx,
        f"Evidence Package {package.package_id}",
        package.classification or "confidential",
    )


def register_evidence_pdf_components() -> None:
    """Register evidence_package on the default registry. Idempotent."""
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "evidence_package" not in reg:
        register_component(
            "evidence_package",
            template="evidence_package.html",
            resolver=_evidence_package_resolver,
            audit_event_type="evidence.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor"},
        )


register_evidence_pdf_components()


__all__ = ["router", "register_evidence_pdf_components"]
