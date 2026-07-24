"""Cross-cutting FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, Request

from .auth.models import User
from .auth.rbac import current_user_optional
from .config import Settings, get_settings


def settings_dep() -> Settings:
    return get_settings()


async def get_compliance_client(
    request: Request,
    user: User | None = Depends(current_user_optional),
):  # type: ignore[no-untyped-def]
    """Per-request scoped compliance API client.

    A fresh ComplianceClient is constructed on each call so that the
    `X-On-Behalf-Of` header reflects the current user. If the app already has
    a long-lived client on `app.state` (production), we still wrap it with
    user/request context here.
    """
    from shared.api_client import ComplianceClient

    settings = get_settings()

    return ComplianceClient(
        base_url=str(settings.compliance_api_base_url),
        token=settings.compliance_api_token.get_secret_value(),
        timeout_s=settings.compliance_api_timeout_s,
        ca_bundle=str(settings.compliance_api_ca_bundle) if settings.compliance_api_ca_bundle else None,
        client_cert=str(settings.compliance_api_client_cert) if settings.compliance_api_client_cert else None,
        client_key=str(settings.compliance_api_client_key) if settings.compliance_api_client_key else None,
        user_sub=user.sub if user else None,
        request_id=getattr(request.state, "request_id", None),
        auditor_scope=user.auditor_scope.model_dump(mode="json") if user and user.auditor_scope else None,
    )


__all__ = ["settings_dep", "get_compliance_client"]
