"""OIDC integration — Authlib OAuth client + login/callback/logout routes.

Implements WI-02 + AMD-15 (session rotation on successful login).

The OIDC flow:
    1. GET /auth/login         — generate state + PKCE, redirect to issuer
    2. GET /auth/callback      — validate state, exchange code, fetch userinfo,
                                  build User, ROTATE SESSION, persist
    3. GET /auth/logout        — destroy local session, redirect to end_session
    4. GET /auth/whoami        — JSON describing the current user

The actual call to `record_audit_event` is wired through the compliance API
client (WI-03); failures there are logged but do not block the login response.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode, urlsplit

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from ..config import Settings
from ..logging import bind_request_context, get_logger
from .models import Role, User
from .rbac import map_groups_to_roles, now_utc
from .session import SessionStore

logger = get_logger(__name__)


# ─── Open-redirect defense (F-02) ────────────────────────────────────────────


def safe_next_url(url: str | None) -> str:
    """Return ``url`` only if it is a same-origin relative path; else "/".

    Defends against open-redirect attacks via the ``?next=`` query parameter
    on the OIDC login flow. Acceptable forms:

    * ``/``                 — root
    * ``/some/path``        — same-origin relative path
    * ``/some/path?q=1``    — relative path with query string
    * ``/some/path#anchor`` — relative path with fragment

    Rejected forms (return "/"):

    * ``https://evil.com/`` — absolute URL with scheme
    * ``//evil.com/path``   — protocol-relative URL (network-path reference)
    * ``\\evil.com/path``   — backslash variant some browsers normalise
    * ``javascript:...``    — non-http scheme
    * empty / None / not starting with "/"
    """
    if not url or not isinstance(url, str):
        return "/"
    # Reject control characters and whitespace which can be used to confuse
    # browser URL parsers.
    if any(ch.isspace() or ord(ch) < 0x20 for ch in url):
        return "/"
    # Protocol-relative URLs and backslash variants
    if url.startswith("//") or url.startswith("\\\\") or url.startswith("/\\"):
        return "/"
    # Must start with a single forward slash
    if not url.startswith("/"):
        return "/"
    parsed = urlsplit(url)
    if parsed.scheme or parsed.netloc:
        return "/"
    return url


# ─── Authlib client construction ─────────────────────────────────────────────


def build_oauth_client(settings: Settings) -> OAuth:
    """Build an Authlib OAuth registry with the OIDC provider registered as
    `oidc`. The Authorization Code Flow with PKCE is enforced via
    `code_challenge_method=S256` on the authorize endpoint.
    """
    oauth = OAuth()
    issuer = str(settings.oidc_issuer).rstrip("/")
    server_metadata_url = f"{issuer}/.well-known/openid-configuration"
    oauth.register(
        name="oidc",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        server_metadata_url=server_metadata_url,
        client_kwargs={
            "scope": "openid profile email groups",
            "code_challenge_method": "S256",
        },
    )
    return oauth


# ─── Routes ──────────────────────────────────────────────────────────────────


def build_auth_router(settings: Settings) -> APIRouter:
    """Construct the /auth/* APIRouter. The actual OAuth client and session
    store are pulled off of `request.app.state` at request time, so this function
    is safe to call before app startup.
    """
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.get("/login")
    async def login(request: Request, next: str = "/") -> RedirectResponse:
        """Initiate OIDC Authorization Code with PKCE.

        The ``next`` query parameter is sanitised via :func:`safe_next_url`
        so that an attacker cannot use a crafted login link to redirect the
        user to an external origin after authentication (CWE-601, F-02).
        """
        # In development APP_ENV the OIDC issuer is unreachable; surface the
        # dev-login bypass instead of trying (and failing) to reach the IdP.
        if settings.app_env == "development":
            return RedirectResponse(url=f"/auth/dev-login?role=admin&next={next}", status_code=303)
        # Sanitise the post-login redirect target BEFORE persisting it in the
        # flow record. Even if downstream code is later refactored, the stored
        # value is already safe.
        sanitised_next = safe_next_url(next)
        oauth: OAuth = request.app.state.oauth
        state = secrets.token_urlsafe(24)
        # Stash state + PKCE verifier in a server-side session-id'd dict
        store: SessionStore = request.app.state.session_store
        flow_id = await store.create(
            payload={"flow": "oidc_login", "state": state, "next": sanitised_next},
            ttl_s=600,
        )
        response = await oauth.oidc.authorize_redirect(
            request, str(settings.oidc_redirect_uri), state=state
        )
        # bind flow_id to a short-lived cookie so callback can locate the flow
        cookie_name = getattr(
            request.app.state, "oidc_flow_cookie_name", "cp_oidc_flow"
        )
        response.set_cookie(
            cookie_name,
            flow_id,
            max_age=600,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,
        )
        return response  # type: ignore[no-any-return]

    @router.get("/callback")
    async def callback(request: Request) -> RedirectResponse:
        """Handle OIDC authorization code response and rotate session (AMD-15)."""
        oauth: OAuth = request.app.state.oauth
        store: SessionStore = request.app.state.session_store
        cookie_name = getattr(
            request.app.state, "oidc_flow_cookie_name", "cp_oidc_flow"
        )
        flow_id = request.cookies.get(cookie_name)
        if not flow_id:
            raise HTTPException(status_code=400, detail="missing flow cookie")

        flow = await store.get(flow_id)
        if not flow or flow.get("flow") != "oidc_login":
            raise HTTPException(status_code=400, detail="invalid or expired flow")

        # Validate state from query against stashed
        recv_state = request.query_params.get("state")
        if not recv_state or recv_state != flow.get("state"):
            raise HTTPException(status_code=400, detail="state mismatch")

        # Exchange code → token
        try:
            token = await oauth.oidc.authorize_access_token(request)
        except Exception as exc:  # Authlib raises various subclasses
            logger.warning("oidc.token_exchange_failed", error=str(exc))
            raise HTTPException(status_code=401, detail="code exchange failed") from exc

        userinfo: dict[str, Any] | None = token.get("userinfo")
        if userinfo is None:
            try:
                userinfo = await oauth.oidc.userinfo(token=token)
            except Exception as exc:
                logger.warning("oidc.userinfo_failed", error=str(exc))
                raise HTTPException(status_code=401, detail="userinfo failed") from exc

        # Build User from claims
        user = build_user_from_claims(
            claims=userinfo,
            settings=settings,
            session_id="<placeholder>",  # replaced after rotation
        )

        # ── AMD-15 — Rotate session ──────────────────────────────────────────
        cookie_session_name = getattr(
            request.app.state, "session_cookie_name", "cp_session"
        )
        pre_login_session_id = request.cookies.get(cookie_session_name)

        new_session_payload = {
            "user": user.model_dump(mode="json"),
            "mfa_at": user.mfa_at.isoformat() if user.mfa_at else None,
            "issued_at": user.issued_at.isoformat(),
        }
        new_session_id = await store.rotate(
            old_session_id=pre_login_session_id,
            payload=new_session_payload,
            ttl_s=settings.session_max_age_s,
        )
        # Update the User session_id field and re-persist
        user_with_session = user.model_copy(update={"session_id": new_session_id})
        await store.set(
            new_session_id,
            {**new_session_payload, "user": user_with_session.model_dump(mode="json")},
            ttl_s=settings.session_max_age_s,
        )

        # Discard the flow record
        await store.delete(flow_id)

        bind_request_context(request_id=getattr(request.state, "request_id", "-"), user_id=user.sub)
        logger.info(
            "auth.login_success",
            user_id=user.sub,
            roles=[r.value for r in user.roles],
            pre_login_session_id_hash=(
                hashlib.sha256(pre_login_session_id.encode()).hexdigest()[:16]
                if pre_login_session_id
                else None
            ),
            new_session_id_hash=hashlib.sha256(new_session_id.encode()).hexdigest()[:16],
        )

        # Best-effort audit emission via compliance client (if attached)
        compliance_client = getattr(request.app.state, "compliance_client", None)
        if compliance_client is not None:
            try:
                await compliance_client.record_audit_event(
                    audit_type="auth.session.rotated_on_login",
                    user_id=user.sub,
                    payload={
                        "pre_login_session_id_hash": (
                            hashlib.sha256(pre_login_session_id.encode()).hexdigest()[:16]
                            if pre_login_session_id
                            else None
                        ),
                        "new_session_id_hash": hashlib.sha256(
                            new_session_id.encode()
                        ).hexdigest()[:16],
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("auth.audit_emit_failed", error=str(exc))

        # Issue the new session cookie + redirect.
        # Re-validate the stored next value as defence-in-depth against any
        # case where untrusted data was persisted into the flow record.
        next_url = safe_next_url(flow.get("next"))
        response = RedirectResponse(url=next_url, status_code=303)
        response.set_cookie(
            cookie_session_name,
            new_session_id,
            max_age=settings.session_max_age_s,
            httponly=settings.session_cookie_httponly,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,
        )
        # Drop the flow cookie
        response.delete_cookie(cookie_name)
        return response

    @router.get("/logout")
    async def logout(request: Request) -> RedirectResponse:
        """Destroy local session and redirect to IdP RP-Initiated Logout."""
        store: SessionStore = request.app.state.session_store
        cookie_session_name = getattr(
            request.app.state, "session_cookie_name", "cp_session"
        )
        session_id = request.cookies.get(cookie_session_name)
        if session_id:
            await store.delete(session_id)
            logger.info("auth.logout", session_id_hash=hashlib.sha256(session_id.encode()).hexdigest()[:16])

        end_session = f"{str(settings.oidc_issuer).rstrip('/')}/end-session"
        response = RedirectResponse(
            url=f"{end_session}?{urlencode({'post_logout_redirect_uri': '/'})}",
            status_code=303,
        )
        response.delete_cookie(cookie_session_name)
        return response

    @router.get("/dev-login")
    async def dev_login(request: Request, role: str = "compliance_officer") -> RedirectResponse:
        """DEV-ONLY login bypass. Creates an authenticated session with the
        chosen role. NEVER mounted in production — guarded by app_env check.

        Available roles: admin, compliance_officer, auditor, sme, viewer
        Usage: GET /auth/dev-login?role=admin
        """
        if settings.app_env not in ("development", "test"):
            raise HTTPException(status_code=404, detail="not found")

        try:
            chosen_role = Role(role)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"invalid role; must be one of {[r.value for r in Role]}",
            ) from exc

        store: SessionStore = request.app.state.session_store
        cookie_session_name = getattr(
            request.app.state, "session_cookie_name", "cp_session"
        )
        pre_login_session_id = request.cookies.get(cookie_session_name)

        now = now_utc()
        user = User(
            sub=f"dev-{chosen_role.value}",
            email=f"dev-{chosen_role.value}@localhost",
            name=f"Dev {chosen_role.value.replace('_', ' ').title()}",
            roles=[chosen_role],
            session_id="<placeholder>",
            issued_at=now,
            expires_at=now + timedelta(seconds=settings.session_max_age_s),
            mfa_at=now,
        )

        new_session_payload = {
            "user": user.model_dump(mode="json"),
            "mfa_at": user.mfa_at.isoformat() if user.mfa_at else None,
            "issued_at": user.issued_at.isoformat(),
        }
        new_session_id = await store.rotate(
            old_session_id=pre_login_session_id,
            payload=new_session_payload,
            ttl_s=settings.session_max_age_s,
        )
        user_with_session = user.model_copy(update={"session_id": new_session_id})
        await store.set(
            new_session_id,
            {**new_session_payload, "user": user_with_session.model_dump(mode="json")},
            ttl_s=settings.session_max_age_s,
        )

        logger.warning(
            "auth.dev_login_used",
            role=chosen_role.value,
            sub=user.sub,
            note="DEV-ONLY bypass — must NOT be reachable in production",
        )

        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            cookie_session_name,
            new_session_id,
            max_age=settings.session_max_age_s,
            httponly=settings.session_cookie_httponly,
            secure=settings.session_cookie_secure,
            samesite=settings.session_cookie_samesite,
        )
        return response

    @router.get("/whoami")
    async def whoami(request: Request) -> JSONResponse:
        """JSON description of the authenticated user (used by HTMX consumers)."""
        from .rbac import current_user_optional

        user = await current_user_optional(request)
        if user is None:
            return JSONResponse({"authenticated": False}, status_code=status.HTTP_401_UNAUTHORIZED)
        return JSONResponse(
            {
                "authenticated": True,
                "sub": user.sub,
                "email": user.email,
                "name": user.name,
                "roles": [r.value for r in user.roles],
                "mfa_at": user.mfa_at.isoformat() if user.mfa_at else None,
                "expires_at": user.expires_at.isoformat(),
            }
        )

    return router


# ─── User construction from claims ───────────────────────────────────────────


def build_user_from_claims(
    *,
    claims: dict[str, Any],
    settings: Settings,
    session_id: str,
) -> User:
    """Translate OIDC userinfo/id_token claims into a User principal.

    Group → role mapping is applied; if zero roles result, a 403 is raised
    upstream (no_authorized_role).
    """
    sub = str(claims.get("sub", "")).strip()
    email = str(claims.get("email", "")).strip()
    name = str(claims.get("name") or claims.get("preferred_username") or email).strip()

    if not sub or not email:
        raise HTTPException(status_code=401, detail="missing sub/email in claims")

    groups: list[str] = list(claims.get("groups") or [])
    roles = map_groups_to_roles(groups, settings.group_to_role_map)
    if not roles:
        raise HTTPException(status_code=403, detail="no_authorized_role")

    issued_at = now_utc()
    expires_at = issued_at + timedelta(seconds=settings.session_max_age_s)

    # MFA timestamp from amr/auth_time claims (RFC 8176).
    #
    # F-12: When the IdP returns ``amr`` indicating MFA but omits ``auth_time``,
    # we MUST NOT fall back to ``issued_at`` — that would grant phantom MFA
    # freshness equal to login time, defeating AMD-03 step-up enforcement.
    # Instead, leave ``mfa_at`` as None so an explicit step-up is required.
    amr = claims.get("amr") or []
    mfa_at = None
    if any(method in amr for method in ("mfa", "otp", "hwk", "fpt", "iris", "face")):
        # auth_time is unix seconds when MFA was performed.
        from datetime import datetime, timezone

        auth_time = claims.get("auth_time")
        if isinstance(auth_time, (int, float)):
            mfa_at = datetime.fromtimestamp(auth_time, tz=timezone.utc)
        else:
            # No usable auth_time → no MFA freshness credit.
            mfa_at = None

    auditor_scope = None
    if Role.AUDITOR in roles:
        # Auditor scope claims (custom — provided by IdP or compliance service)
        scope_claims = claims.get("auditor_scope")
        if scope_claims:
            from .models import AuditorScope

            try:
                auditor_scope = AuditorScope.model_validate(scope_claims)
            except Exception:  # noqa: BLE001
                logger.warning("auth.auditor_scope_invalid", sub=sub)

    return User(
        sub=sub,
        email=email,
        name=name,
        roles=roles,
        auditor_scope=auditor_scope,
        mfa_at=mfa_at,
        session_id=session_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


__all__ = [
    "build_oauth_client",
    "build_auth_router",
    "build_user_from_claims",
    "safe_next_url",
]
