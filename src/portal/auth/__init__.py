"""Authentication & RBAC — WI-02.

Public exports:
    Role, AuditorScope, User, AuthContext  — pydantic models
    current_user, require_role, require_any_role  — FastAPI dependencies
    require_mfa  — MFA step-up dependency (AMD-03 binding lives in WI-12)
    SessionStore  — server-side session store with rotation (AMD-15)
"""

from .models import AuditorScope, AuthContext, Role, User
from .rbac import current_user, current_user_optional, require_any_role, require_role
from .mfa import MfaNonceManager, StepUpRequired, require_mfa
from .session import InMemorySessionStore, RedisSessionStore, SessionStore

__all__ = [
    "AuditorScope",
    "AuthContext",
    "Role",
    "User",
    "current_user",
    "current_user_optional",
    "require_role",
    "require_any_role",
    "require_mfa",
    "MfaNonceManager",
    "StepUpRequired",
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
]
