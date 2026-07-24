"""MFA step-up dependency + decision_nonce binding (AMD-03 primitive).

AMD-03 (CISO C-3b): the MFA freshness window is 60 seconds AND the nonce is
single-use bound to (user_sub, decision_action). This module exposes the
primitive used by WI-06/WI-11/WI-12 sign actions.

Backend selection (F-05)
------------------------

In-process ``dict`` storage is unsafe under multi-worker uvicorn deployments
because each worker has its own ``MfaNonceManager`` instance — a nonce
issued in worker A is invisible to worker B. ``MfaNonceManager`` therefore
delegates to a pluggable backend:

* :class:`_InMemoryNonceBackend` — used in unit tests and single-worker dev.
* :class:`_RedisNonceBackend`    — used in production, shares the same Redis
                                    instance as the session store.

The public ``MfaNonceManager`` API (``issue`` / ``consume`` / ``fingerprint``)
is unchanged so existing routers do not need to be updated.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

from fastapi import Depends, HTTPException, Request, status

from .models import User
from .rbac import current_user, now_utc


class StepUpRequired(HTTPException):
    """Raised when MFA freshness is stale. Caught by the exception handler
    that emits an HTMX-aware 302 to /auth/login?stepup=1."""

    def __init__(self, *, max_age_s: int, redirect_url: str | None = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="mfa step-up required",
            headers={"WWW-Authenticate": f'StepUp max_age="{max_age_s}"'},
        )
        self.max_age_s = max_age_s
        self.redirect_url = redirect_url


def require_mfa(max_age_s: int = 300) -> Callable[..., Awaitable[User]]:
    """FastAPI dependency — requires `mfa_at` within `max_age_s` seconds.

    For HTMX-targeted endpoints, the calling router should catch StepUpRequired
    and emit an `HX-Redirect` header. For full-page requests, the centralized
    exception handler (security/exception_handlers.py) emits a 302.

    F-12 — when ``mfa_at`` is missing from the session entirely (e.g. the
    IdP omitted ``auth_time``), step-up is required. The check is explicit
    rather than relying on truthiness so a future refactor cannot widen
    the criterion accidentally.
    """

    async def _dep(user: User = Depends(current_user)) -> User:
        if user.mfa_at is None:
            raise StepUpRequired(max_age_s=max_age_s)
        age = (now_utc() - user.mfa_at).total_seconds()
        if age > max_age_s:
            raise StepUpRequired(max_age_s=max_age_s)
        return user

    _dep.__name__ = f"require_mfa_{max_age_s}"
    return _dep


# ─── decision_nonce manager (AMD-03) ─────────────────────────────────────────


@dataclass(frozen=True)
class _NonceRecord:
    user_sub: str
    action: str
    issued_at: float


class _NonceBackend(Protocol):
    """Minimal contract a nonce backend must satisfy.

    All methods are synchronous so the public ``MfaNonceManager`` API can
    remain synchronous (callers in routers do not currently ``await`` it).
    """

    def setnx(self, key: str, value: str, ttl_s: int) -> bool: ...

    def getdel(self, key: str) -> str | None: ...

    def gc(self) -> int: ...


class _InMemoryNonceBackend:
    """Single-process backend — only safe for tests and single-worker dev."""

    def __init__(self) -> None:
        self._records: dict[str, tuple[str, float]] = {}

    def setnx(self, key: str, value: str, ttl_s: int) -> bool:
        if key in self._records:
            return False
        self._records[key] = (value, time.time() + ttl_s)
        return True

    def getdel(self, key: str) -> str | None:
        record = self._records.pop(key, None)
        if record is None:
            return None
        value, expiry = record
        if time.time() > expiry:
            return None
        return value

    def gc(self) -> int:
        now = time.time()
        expired = [k for k, (_, exp) in self._records.items() if exp < now]
        for k in expired:
            self._records.pop(k, None)
        return len(expired)


class _RedisNonceBackend:
    """Redis-backed backend — safe across uvicorn workers (F-05).

    Uses the synchronous ``redis.Redis`` client so the nonce API can stay
    synchronous. The atomicity of ``GETDEL`` (Redis 6.2+) makes consumption
    a single round-trip; for older Redis we fall back to a Lua script.

    Keys: ``mfa_nonce:{token}``
    Value: JSON-encoded ``{"sub": ..., "action": ..., "issued_at": ...}``
    TTL:  ``max_age_s`` seconds (Redis enforces expiry independently of
          the manager's clock).
    """

    _CONSUME_LUA = (
        "local v = redis.call('GET', KEYS[1]); "
        "if v then redis.call('DEL', KEYS[1]); end; "
        "return v"
    )
    _KEY_PREFIX = "mfa_nonce:"

    def __init__(self, client: Any) -> None:
        self._client = client
        # Best-effort: register the Lua script so we can fall back when
        # the deployed Redis is older than 6.2 (no GETDEL).
        try:
            self._consume_script = client.register_script(self._CONSUME_LUA)
        except Exception:  # noqa: BLE001 — fakeredis or odd builds
            self._consume_script = None

    def _full_key(self, key: str) -> str:
        return f"{self._KEY_PREFIX}{key}"

    def setnx(self, key: str, value: str, ttl_s: int) -> bool:
        # ``SET key value NX EX ttl`` is atomic on the server.
        result = self._client.set(self._full_key(key), value, nx=True, ex=ttl_s)
        return bool(result)

    def getdel(self, key: str) -> str | None:
        full = self._full_key(key)
        # Prefer GETDEL when available; fall back to a Lua script otherwise.
        getdel = getattr(self._client, "getdel", None)
        if callable(getdel):
            try:
                raw = getdel(full)
            except Exception:  # noqa: BLE001 — older Redis returns NOTSUPPORTED
                raw = None
                getdel = None
        if not callable(getdel):
            if self._consume_script is None:
                # Last-resort: pipeline GET + DEL (still atomic per
                # connection).
                with self._client.pipeline(transaction=True) as pipe:
                    pipe.get(full)
                    pipe.delete(full)
                    raw, _ = pipe.execute()
            else:
                raw = self._consume_script(keys=[full])
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw)

    def gc(self) -> int:
        # Redis handles TTL expiry server-side; nothing to do here.
        return 0


class MfaNonceManager:
    """Single-use MFA nonces bound to (user_sub, action).

    Used by WI-06 / WI-11 / WI-12 to prevent MFA replay across decisions.
    A nonce is:
        - issued at sign-action initiation (max_age_s seconds before sign)
        - bound to (user_sub, action_id) — e.g., ("alice", "gate.decide:abc")
        - consumed on successful decision; subsequent reuse → False (replay)

    F-05 — the storage backend is pluggable. Pass ``redis_client=...`` to
    use the Redis backend (production); omit it for the in-memory backend
    (tests, single-worker dev).
    """

    def __init__(
        self,
        max_age_s: int = 60,
        *,
        redis_client: Any | None = None,
        backend: _NonceBackend | None = None,
    ) -> None:
        self.max_age_s = max_age_s
        if backend is not None:
            self._backend: _NonceBackend = backend
        elif redis_client is not None:
            self._backend = _RedisNonceBackend(redis_client)
        else:
            self._backend = _InMemoryNonceBackend()

    def issue(self, user_sub: str, action: str) -> str:
        """Generate a nonce token bound to (user_sub, action).

        Implementation note: ``SET NX`` is used so a fantastically unlikely
        collision still cannot silently overwrite an existing record.
        """
        token = secrets.token_urlsafe(32)
        record = json.dumps(
            {
                "sub": user_sub,
                "action": action,
                "issued_at": time.time(),
            },
            separators=(",", ":"),
        )
        # In the (statistically impossible) collision case, reroll.
        for _ in range(3):
            if self._backend.setnx(token, record, self.max_age_s):
                return token
            token = secrets.token_urlsafe(32)
        raise RuntimeError("could not allocate unique mfa nonce")

    def consume(self, token: str, user_sub: str, action: str) -> bool:
        """Validate + consume a nonce. Returns True iff valid; otherwise False.

        Reasons for False:
            - unknown token (never issued or already consumed)
            - bound to a different user_sub or action
            - older than max_age_s
        """
        raw = self._backend.getdel(token)
        if raw is None:
            return False
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return False
        if not isinstance(payload, dict):
            return False
        if payload.get("sub") != user_sub or payload.get("action") != action:
            return False
        issued_at = payload.get("issued_at")
        if not isinstance(issued_at, (int, float)):
            return False
        if time.time() - issued_at > self.max_age_s:
            return False
        return True

    @staticmethod
    def fingerprint(token: str) -> str:
        """Hash token for audit logs (never log raw tokens)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]

    def gc(self) -> int:
        """Remove expired records. Returns count purged.

        Redis backend is a no-op (TTL handles expiry server-side).
        """
        return self._backend.gc()


__all__ = ["StepUpRequired", "require_mfa", "MfaNonceManager"]
