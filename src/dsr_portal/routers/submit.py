"""Public DSR portal — submission, status check, identity-proof upload, receipt.

Routes (mounted at root of the public app):

    GET  /                        — landing
    GET  /dsr/submit              — intake form
    POST /dsr/submit              — submit (CAPTCHA, AMD-11 size limit)
    GET  /dsr/status              — status check form
    POST /dsr/status              — status lookup (capability=STATUS_CHECK)
    POST /dsr/identity-upload     — re-upload (capability=IDENTITY_UPLOAD)
    GET  /dsr/receipt             — PDF receipt (capability=RECEIPT_DOWNLOAD)

AMD-05 — capability ACL enforced via require_capability dependency on
        STATUS_CHECK / IDENTITY_UPLOAD / RECEIPT_DOWNLOAD routes. SUBMIT does
        not require a token (public landing).
AMD-11 — body size limited to 5MB at FastAPI; nginx allows 8MB headroom.
AMD-26 — uploaded identity proof goes to the compliance service for ClamAV;
        portal returns 422 if scan_status in {infected, unscannable}.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.token import (
    PublicToken,
    PublicTokenManager,
    TokenCapability,
    require_capability,
)
from ..captcha import verify_captcha
from ..malware_scan import MAX_BYTES, is_allowed_content_type, scan_file

router = APIRouter()


def _templates_dep(request: Request) -> Jinja2Templates:
    return request.app.state.templates


def _client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _get_compliance_client(request: Request) -> ComplianceClient:
    """Public portal uses a single service-account token (separate from internal).

    The token's capability ACL is enforced by the compliance service.
    """
    factory = request.app.state.compliance_client_factory
    return factory(request)


# ─────────────────────────────────────────────────────────────────────────────
# Landing + submit
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/", response_class=HTMLResponse, name="public_landing")
async def public_landing(
    request: Request,
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "landing.html",
        {"settings": request.app.state.settings_summary},
    )


@router.get("/dsr/submit", response_class=HTMLResponse, name="public_submit_form")
async def public_submit_form(
    request: Request,
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "intake_form.html",
        {"settings": request.app.state.settings_summary},
    )


@router.post("/dsr/submit", response_class=HTMLResponse, name="public_submit")
async def public_submit(
    request: Request,
    request_type: str = Form(...),
    subject_name: str = Form(..., min_length=1, max_length=200),
    subject_email: str = Form(..., min_length=3, max_length=200),
    description: str = Form(default=""),
    captcha_token: str = Form(default=""),
    website: str = Form(default=""),  # honeypot
    identity_proof: UploadFile | None = File(default=None),
    templates: Jinja2Templates = Depends(_templates_dep),
    client: ComplianceClient = Depends(_get_compliance_client),
) -> HTMLResponse:
    settings = request.app.state.settings_summary

    # Honeypot — return success page with bogus reference, no service call.
    if website.strip():
        bogus_ref = f"DSR-PUB-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-XXXX"
        return templates.TemplateResponse(
            request,
            "receipt.html",
            {"reference": bogus_ref, "honeypot": True, "settings": settings},
        )

    # Validate request type.
    valid_types = {
        "access",
        "rectification",
        "erasure",
        "restriction",
        "portability",
        "objection",
        "automated_decision_review",
    }
    if request_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid request_type: {request_type}",
        )

    # CAPTCHA verification.
    captcha_result = await verify_captcha(
        token=captcha_token,
        remote_ip=_client_ip(request),
        provider=settings.get("captcha_provider", "none"),
        secret=settings.get("captcha_secret", ""),
        app_env=settings.get("app_env", "test"),
    )
    if not captcha_result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"captcha_failed: {captcha_result.error}",
        )

    # Identity proof — AMD-11 size + AMD-26 scan path.
    identity_proof_id: str | None = None
    if identity_proof and identity_proof.filename:
        body = await identity_proof.read()
        if len(body) > MAX_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"file too large: {len(body)} > {MAX_BYTES}",
            )
        # F-08 / F-10 — reject any content-type outside the strict allowlist
        # (image/jpeg, image/png, application/pdf) BEFORE forwarding to the
        # service. Generic application/octet-stream and unknown MIME types are
        # rejected here so the service never sees them.
        if not is_allowed_content_type(identity_proof.content_type):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="identity_proof_unsupported_media_type",
            )
        # Pre-scan locally (advisory).
        local = scan_file(body, content_type=identity_proof.content_type)
        if local.status == "unscannable":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"identity_proof_unscannable: {local.reason}",
            )
        # F-08 — "suspicious" magic-byte mismatch is rejected at the portal so
        # polyglot files never reach the service-side scanner.
        if local.status == "suspicious":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="identity_proof_rejected",
            )
        # Service-side scan via upload (AMD-26 — definitive verdict).
        scan = await client.upload_identity_proof(
            reference="pending",
            email=subject_email,
            filename=identity_proof.filename,
            content_type=identity_proof.content_type or "application/octet-stream",
            file_bytes=body,
        )
        if scan.scan_status not in {"clean", "pending"}:
            # Generic error — never echo filename or content (info leak).
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="identity_proof_rejected",
            )
        identity_proof_id = scan.proof_id

    # Submit — service generates reference number.
    result = await client.submit_public_dsr(
        request_type=request_type,
        subject_name=subject_name,
        subject_email=subject_email,
        description=description or None,
        identity_proof_id=identity_proof_id,
    )

    # Issue a STATUS_CHECK + IDENTITY_UPLOAD + RECEIPT_DOWNLOAD token bundle.
    # F-03 — IDENTITY_UPLOAD must be a separately issued, separately scoped
    # capability token (per AMD-05). Each capability gets its own signed
    # token; the submitter receives all three at submission time so the public
    # portal can support follow-up flows (status check, re-upload, receipt
    # download) without ever needing to relax the ACL on individual routes.
    token_mgr: PublicTokenManager = request.app.state.public_token_mgr
    status_token = token_mgr.issue(
        reference=result.reference,
        email=subject_email,
        capability=TokenCapability.STATUS_CHECK,
    )
    identity_upload_token = token_mgr.issue(
        reference=result.reference,
        email=subject_email,
        capability=TokenCapability.IDENTITY_UPLOAD,
    )
    receipt_token = token_mgr.issue(
        reference=result.reference,
        email=subject_email,
        capability=TokenCapability.RECEIPT_DOWNLOAD,
    )
    return templates.TemplateResponse(
        request,
        "receipt.html",
        {
            "reference": result.reference,
            "request_id": result.request_id,
            "submitted_at": result.submitted_at.isoformat(),
            "status_token": status_token,
            "identity_upload_token": identity_upload_token,
            "receipt_token": receipt_token,
            "settings": settings,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Status check (AMD-05 STATUS_CHECK capability)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/dsr/status", response_class=HTMLResponse, name="public_status_form")
async def public_status_form(
    request: Request,
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "status_check.html",
        {"settings": request.app.state.settings_summary},
    )


@router.post("/dsr/status", response_class=HTMLResponse, name="public_status_check")
async def public_status_check(
    request: Request,
    reference: str = Form(...),
    email: str = Form(...),
    captcha_token: str = Form(default=""),
    templates: Jinja2Templates = Depends(_templates_dep),
    client: ComplianceClient = Depends(_get_compliance_client),
    public_token: PublicToken = Depends(
        require_capability(TokenCapability.STATUS_CHECK)
    ),
) -> HTMLResponse:
    """Look up the status of a submitted DSR.

    AMD-05 capability ACL is enforced via
    ``require_capability(TokenCapability.STATUS_CHECK)``, matching the
    IDENTITY_UPLOAD and RECEIPT_DOWNLOAD routes. The token is issued at
    submission time alongside those two. Previously this route documented the
    STATUS_CHECK capability but never enforced it, so CAPTCHA plus
    (reference, email) were the only gate on someone else's request status.
    """
    settings = request.app.state.settings_summary

    captcha_result = await verify_captcha(
        token=captcha_token,
        remote_ip=_client_ip(request),
        provider=settings.get("captcha_provider", "none"),
        secret=settings.get("captcha_secret", ""),
        app_env=settings.get("app_env", "test"),
    )
    if not captcha_result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="captcha_failed",
        )

    try:
        public_status = await client.check_dsr_status_by_token(
            reference=reference, email=email
        )
    except Exception:  # noqa: BLE001
        # Generic 404 wording — must not distinguish wrong-ref vs wrong-email
        return templates.TemplateResponse(
            request,
            "status_check.html",
            {
                "settings": settings,
                "error": "We could not find a request matching those details.",
            },
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return templates.TemplateResponse(
        request,
        "status_check.html",
        {
            "settings": settings,
            "status_payload": public_status.model_dump(mode="json"),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Identity-upload (AMD-05 IDENTITY_UPLOAD capability)
# ─────────────────────────────────────────────────────────────────────────────


@router.post(
    "/dsr/identity-upload",
    response_class=HTMLResponse,
    name="public_identity_upload",
)
async def public_identity_upload(
    request: Request,
    reference: str = Form(...),
    email: str = Form(...),
    captcha_token: str = Form(default=""),
    identity_proof: UploadFile = File(...),
    templates: Jinja2Templates = Depends(_templates_dep),
    client: ComplianceClient = Depends(_get_compliance_client),
    public_token: PublicToken = Depends(
        require_capability(TokenCapability.IDENTITY_UPLOAD)
    ),
) -> HTMLResponse:
    """Re-upload identity proof when status is `identity_insufficient`.

    F-03 — AMD-05 capability ACL is enforced via
    ``require_capability(TokenCapability.IDENTITY_UPLOAD)``. The token is
    issued at submission time (alongside STATUS_CHECK and RECEIPT_DOWNLOAD)
    and is required on every call. CAPTCHA + (reference, email) are an
    additional layer, not the primary gate.
    """
    settings = request.app.state.settings_summary

    # Cross-check that (reference, email) on the form match the values
    # baked into the signed capability token. This prevents a user with a
    # valid token for request A from re-uploading on request B by typing a
    # different reference into the form.
    if (
        public_token.reference != reference
        or public_token.email.lower() != email.lower().strip()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="token_reference_mismatch",
        )

    captcha_result = await verify_captcha(
        token=captcha_token,
        remote_ip=_client_ip(request),
        provider=settings.get("captcha_provider", "none"),
        secret=settings.get("captcha_secret", ""),
        app_env=settings.get("app_env", "test"),
    )
    if not captcha_result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="captcha_failed",
        )

    body = await identity_proof.read()
    if len(body) > MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="file_too_large",
        )

    # F-08 / F-10 — reject any content-type outside the strict allowlist
    # before invoking the service-side malware scanner.
    if not is_allowed_content_type(identity_proof.content_type):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="identity_proof_unsupported_media_type",
        )

    local = scan_file(body, content_type=identity_proof.content_type)
    if local.status == "unscannable":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="identity_proof_unscannable",
        )
    # F-08 — reject "suspicious" magic-byte mismatches at the portal layer.
    if local.status == "suspicious":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="identity_proof_rejected",
        )

    scan = await client.upload_identity_proof(
        reference=reference,
        email=email,
        filename=identity_proof.filename or "upload",
        content_type=identity_proof.content_type or "application/octet-stream",
        file_bytes=body,
    )
    if scan.scan_status not in {"clean", "pending"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="identity_proof_rejected",
        )

    return templates.TemplateResponse(
        request,
        "identity_upload.html",
        {
            "settings": settings,
            "reference": reference,
            "scan_status": scan.scan_status,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Receipt (AMD-05 RECEIPT_DOWNLOAD capability)
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/dsr/receipt", response_class=HTMLResponse, name="public_receipt")
async def public_receipt(
    request: Request,
    templates: Jinja2Templates = Depends(_templates_dep),
    client: ComplianceClient = Depends(_get_compliance_client),
    public_token: PublicToken = Depends(
        require_capability(TokenCapability.RECEIPT_DOWNLOAD)
    ),
) -> HTMLResponse:
    receipt = await client.get_dsr_receipt(
        reference=public_token.reference, email=public_token.email
    )
    return templates.TemplateResponse(
        request,
        "receipt.html",
        {
            "reference": public_token.reference,
            "receipt_payload": receipt,
            "settings": request.app.state.settings_summary,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/healthz", name="public_healthz")
async def public_healthz() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK, content={"status": "ok"}
    )


__all__ = ["router"]
