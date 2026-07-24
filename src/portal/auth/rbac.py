"""RBAC — `current_user`, `require_role`, `require_any_role` FastAPI dependencies."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from fastapi import Depends, HTTPException, Request, status

from .models import Role, User
from .session import SessionStore


def _get_session_store(request: Request) -> SessionStore:
    """Pull the session store off of app.state. Raises 500 if not configured."""
    store = getattr(request.app.state, "session_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="session store not configured",
        )
    return store


async def current_user_optional(request: Request) -> User | None:
    """Returns the User if a valid session exists, else None.

    Reads the session_id from the cookie, looks up the payload, validates expiry,
    and reconstructs the User pydantic model.
    """
    cookie_name = getattr(request.app.state, "session_cookie_name", "cp_session")
    session_id = request.cookies.get(cookie_name)
    if not session_id:
        return None

    store = _get_session_store(request)
    payload = await store.get(session_id)
    if not payload:
        return None

    user_dict: dict[str, Any] | None = payload.get("user")
    if not user_dict:
        return None

    try:
        user = User.model_validate(user_dict)
    except Exception:
        return None

    if user.is_expired():
        await store.delete(session_id)
        return None

    return user


async def current_user(request: Request) -> User:
    """Required-auth dependency. Raises 401 if no valid session."""
    user = await current_user_optional(request)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Session"},
        )
    return user


def require_role(role: Role) -> Callable[..., Awaitable[User]]:
    """Dependency factory — raises 403 if user lacks the role."""

    async def _dep(user: User = Depends(current_user)) -> User:
        if not user.has_role(role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role '{role.value}' required",
            )
        return user

    _dep.__name__ = f"require_role_{role.value}"
    return _dep


def require_any_role(*roles: Role) -> Callable[..., Awaitable[User]]:
    """Dependency factory — passes if user has at least one of the listed roles."""
    if not roles:
        raise ValueError("require_any_role: at least one role required")

    async def _dep(user: User = Depends(current_user)) -> User:
        if not user.has_any_role(*roles):
            allowed = ",".join(r.value for r in roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"one of [{allowed}] required",
            )
        return user

    _dep.__name__ = f"require_any_role_{'_'.join(r.value for r in roles)}"
    return _dep


def map_groups_to_roles(idp_groups: list[str], group_to_role: dict[str, str]) -> list[Role]:
    """Translate IdP group names to portal Role enums.

    Unknown groups are silently ignored. Empty result means user has no
    portal-mapped role and login should be rejected with 403 no_authorized_role.
    """
    roles: list[Role] = []
    for g in idp_groups:
        role_name = group_to_role.get(g)
        if role_name is None:
            continue
        try:
            roles.append(Role(role_name))
        except ValueError:
            continue
    # de-dupe preserving order
    seen: set[Role] = set()
    deduped: list[Role] = []
    for r in roles:
        if r not in seen:
            seen.add(r)
            deduped.append(r)
    return deduped


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


__all__ = [
    "current_user",
    "current_user_optional",
    "require_role",
    "require_any_role",
    "map_groups_to_roles",
    "now_utc",
]
