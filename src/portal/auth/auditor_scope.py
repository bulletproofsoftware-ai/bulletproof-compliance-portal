"""WI-07 — Auditor engagement-scope enforcement.

When a user with `Role.AUDITOR` accesses any artifact (audit event, evidence
package, gate decision, etc.), the portal MUST:

  1. Confirm the user has an active engagement (REQ-CPL-033 — time-boxed,
     no renewal).
  2. Reject access if the engagement is expired or revoked (REQ-CPL-033/034 —
     instant revocation).
  3. Reject access if the requested artifact type is outside the engagement's
     `allowed_artifact_types` (REQ-CPL-035 — minimum-required-scope).
  4. Log every artifact view to the engagement access log (REQ-CPL-034 —
     access logging on every view).

This module exposes:

    * `EngagementInactive` — exception for expired/revoked engagements.
    * `require_active_engagement` — FastAPI dependency that runs all four
      checks and logs the access. Returns the engagement object.
    * `enforce_artifact_scope` — non-dependency variant for routes that need
      to log access AFTER they've fetched the artifact (e.g., to record the
      artifact id in the audit trail).

Non-auditor users are short-circuited: the dependency returns immediately
without contacting the compliance service, so the cost is zero on the
common path.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, status

from shared.api_client import AuditorEngagement, ComplianceClient

from ..dependencies import get_compliance_client
from ..logging import get_logger
from .models import Role, User
from .rbac import current_user

logger = get_logger(__name__)


class EngagementInactive(HTTPException):
    """Raised when an auditor's engagement is expired, revoked, or missing.

    The exception handler logs the user out (status_code=403) and emits an
    audit event so the admin can see attempted access after revocation.
    """

    def __init__(self, *, reason: str):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"engagement_{reason}",
        )
        self.reason = reason


async def _verify_engagement(
    user: User, client: ComplianceClient
) -> AuditorEngagement:
    """Pull the engagement record for the auditor and validate state + window."""
    if user.auditor_scope is None:
        raise EngagementInactive(reason="missing")
    engagement_id = user.auditor_scope.engagement_id
    try:
        engagement = await client.get_engagement(engagement_id)
    except Exception as exc:  # noqa: BLE001
        # If the compliance service can't confirm the engagement, FAIL CLOSED
        # — auditor access is denied.
        logger.warning(
            "auditor.engagement_lookup_failed",
            engagement_id=engagement_id,
            user_sub=user.sub,
            error=str(exc),
        )
        raise EngagementInactive(reason="lookup_failed") from exc

    state = (engagement.state or "").lower()
    if state == "revoked":
        raise EngagementInactive(reason="revoked")
    if state == "expired":
        raise EngagementInactive(reason="expired")
    now = datetime.now(UTC)
    if engagement.engagement_end and now > engagement.engagement_end:
        raise EngagementInactive(reason="expired")
    if engagement.engagement_start and now < engagement.engagement_start:
        raise EngagementInactive(reason="not_yet_active")
    return engagement


async def require_active_engagement(
    request: Request,
    user: User = Depends(current_user),
    client: ComplianceClient = Depends(get_compliance_client),
) -> User:
    """FastAPI dependency — confirms an auditor's engagement is active.

    For non-auditor users, returns the user unchanged.

    For auditors:
      * Fetches the engagement record from the compliance service.
      * Rejects expired, revoked, or out-of-window engagements with 403.
      * Returns the user (the engagement is also stashed on `request.state`
        for downstream handlers to read without a second lookup).
    """
    if not user.has_role(Role.AUDITOR):
        return user

    engagement = await _verify_engagement(user, client)
    request.state.auditor_engagement = engagement
    return user


async def log_artifact_view(
    user: User,
    client: ComplianceClient,
    *,
    artifact_type: str,
    artifact_id: str,
    action: str = "view",
) -> None:
    """REQ-CPL-034 — log every artifact VIEW (not just downloads).

    Silently no-ops for non-auditor users. For auditors, calls the compliance
    service `log_engagement_access` helper. Failure to log is logged locally
    but does NOT block the request — the artifact view still proceeds. (If
    the audit chain itself is unavailable, the portal degrades to local logs.)
    """
    if not user.has_role(Role.AUDITOR) or user.auditor_scope is None:
        return
    try:
        await client.log_engagement_access(
            user.auditor_scope.engagement_id,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            action=action,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "auditor.access_log_failed",
            engagement_id=user.auditor_scope.engagement_id,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            error=str(exc),
        )


def enforce_artifact_scope(user: User, *, artifact_type: str) -> None:
    """REQ-CPL-035 — reject if artifact_type is outside engagement scope.

    Cheap to call from any handler. Non-auditor users pass through.
    """
    if not user.has_role(Role.AUDITOR):
        return
    scope = user.auditor_scope
    if scope is None:
        raise EngagementInactive(reason="missing")
    if scope.allowed_artifact_types and artifact_type not in scope.allowed_artifact_types:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"artifact_type {artifact_type!r} outside engagement scope",
        )


__all__ = [
    "EngagementInactive",
    "require_active_engagement",
    "log_artifact_view",
    "enforce_artifact_scope",
]
