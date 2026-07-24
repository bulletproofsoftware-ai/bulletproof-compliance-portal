"""Auth pydantic models — Role, AuditorScope, User, AuthContext."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Role(StrEnum):
    """5-role RBAC matrix per REQ-CPL-002."""

    ADMIN = "admin"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    SME = "sme"
    VIEWER = "viewer"


class AuditorScope(BaseModel):
    """Engagement-bound scope for an auditor user.

    Populated only when role == auditor; sourced from IdP claims or compliance
    service. Translates into query params on every WI-03 list/get call.
    """

    model_config = ConfigDict(frozen=True)

    engagement_id: str
    engagement_start: datetime
    engagement_end: datetime  # hard expiry, no renewal (REQ-CPL-033)
    date_range_start: datetime
    date_range_end: datetime
    allowed_artifact_types: list[str] = Field(default_factory=list)
    allowed_project_ids: list[str] | None = None  # None = all in scope


class User(BaseModel):
    """Authenticated principal."""

    model_config = ConfigDict(frozen=False)

    sub: str  # OIDC subject — stable user ID
    email: str
    name: str
    roles: list[Role] = Field(default_factory=list)
    auditor_scope: AuditorScope | None = None
    mfa_at: datetime | None = None
    session_id: str
    issued_at: datetime
    expires_at: datetime

    def has_role(self, role: Role) -> bool:
        return role in self.roles

    def has_any_role(self, *roles: Role) -> bool:
        return any(r in self.roles for r in roles)

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at


class AuthContext(BaseModel):
    """Per-request derived auth context."""

    model_config = ConfigDict(frozen=True)

    user: User
    request_id: str
    ip: str
    user_agent: str
