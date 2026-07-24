"""Server-side session store with explicit rotation per AMD-15.

Two backends:
  - InMemorySessionStore — used for tests and local dev when redis_url is empty
  - RedisSessionStore     — production backend

A session is identified by `session_id` (256 bits of entropy, base64url-encoded
via `secrets.token_urlsafe(32)`). The session_id is what travels in the cookie;
the user payload lives server-side. Rotation on login is enforced by the OIDC
callback (see auth/oidc.py) which calls `rotate(old_session_id, new_payload)`.
"""

from __future__ import annotations

import json
import secrets
import time
from abc import ABC, abstractmethod
from typing import Any


class SessionStore(ABC):
    """Abstract server-side session store."""

    @abstractmethod
    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Return the session payload or None if absent/expired."""

    @abstractmethod
    async def set(self, session_id: str, payload: dict[str, Any], ttl_s: int) -> None:
        """Store payload under session_id with TTL."""

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Invalidate the session. Returns True if it existed."""

    @abstractmethod
    async def exists(self, session_id: str) -> bool:
        """Cheap existence check."""

    async def create(self, payload: dict[str, Any], ttl_s: int) -> str:
        """Generate a fresh session_id, persist payload, return id."""
        session_id = secrets.token_urlsafe(32)  # 256 bits
        await self.set(session_id, payload, ttl_s)
        return session_id

    async def rotate(
        self,
        old_session_id: str | None,
        payload: dict[str, Any],
        ttl_s: int,
    ) -> str:
        """AMD-15 — invalidate old session (if any), create new one.

        Always returns a fresh session_id. The old id is deleted unconditionally
        if it exists; failure to delete is logged at upper layers but does NOT
        block issuance of the new session.
        """
        if old_session_id:
            await self.delete(old_session_id)
        return await self.create(payload, ttl_s)


class InMemorySessionStore(SessionStore):
    """Process-local store. NOT suitable for multi-worker production."""

    def __init__(self) -> None:
        # session_id -> (payload_json, expires_at_epoch)
        self._store: dict[str, tuple[str, float]] = {}

    async def get(self, session_id: str) -> dict[str, Any] | None:
        entry = self._store.get(session_id)
        if entry is None:
            return None
        payload_json, expires_at = entry
        if time.time() >= expires_at:
            self._store.pop(session_id, None)
            return None
        return json.loads(payload_json)

    async def set(self, session_id: str, payload: dict[str, Any], ttl_s: int) -> None:
        self._store[session_id] = (json.dumps(payload, default=str), time.time() + ttl_s)

    async def delete(self, session_id: str) -> bool:
        return self._store.pop(session_id, None) is not None

    async def exists(self, session_id: str) -> bool:
        entry = self._store.get(session_id)
        if entry is None:
            return False
        if time.time() >= entry[1]:
            self._store.pop(session_id, None)
            return False
        return True

    def clear(self) -> None:
        """Test helper."""
        self._store.clear()


class RedisSessionStore(SessionStore):
    """Redis-backed store. Uses async redis client."""

    def __init__(self, redis_client: Any, *, key_prefix: str = "cp:session:") -> None:
        self._redis = redis_client
        self._prefix = key_prefix

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    async def get(self, session_id: str) -> dict[str, Any] | None:
        raw = await self._redis.get(self._key(session_id))
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return json.loads(raw)

    async def set(self, session_id: str, payload: dict[str, Any], ttl_s: int) -> None:
        await self._redis.set(
            self._key(session_id),
            json.dumps(payload, default=str),
            ex=ttl_s,
        )

    async def delete(self, session_id: str) -> bool:
        result = await self._redis.delete(self._key(session_id))
        return bool(result)

    async def exists(self, session_id: str) -> bool:
        return bool(await self._redis.exists(self._key(session_id)))


__all__ = ["SessionStore", "InMemorySessionStore", "RedisSessionStore"]
