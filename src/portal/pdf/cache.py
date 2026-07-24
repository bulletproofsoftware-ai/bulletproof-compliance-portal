"""PDF cache with cross-auditor isolation (AMD-13).

The cache key MUST include a `watermark_id` derived from the auditor's
identity AND engagement so two different auditors (or the same auditor across
engagements) never share a cache entry. Otherwise we leak one auditor's
watermarked PDF to another.

    watermark_id = base64url( sha256(auditor_sub || "|" || engagement_id) )[:22]

The same `watermark_id` is also written into PDF /Metadata as
`/X-Compliance-Watermark-Id` (see metadata.py + AMD-06) so audit-event
correlation against served PDFs is possible after the fact.

Backend: in-process `cachetools.TTLCache` with LRU eviction. A future
deployment may swap in a Redis backend; the public API does not change.
"""

from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any

from cachetools import TTLCache

# ── Defaults ─────────────────────────────────────────────────────────────────
DEFAULT_TTL_S: int = 300  # 5 minutes
DEFAULT_MAX_ENTRIES: int = 256  # ~256 PDFs cached per process; LRU evicts older


def compute_watermark_id(auditor_sub: str, engagement_id: str) -> str:
    """Deterministic watermark identifier (AMD-13).

    Properties:
      - Deterministic across processes (cache hits across worker restarts)
      - Different auditor OR different engagement => different watermark_id
      - 22-char base64url string, safe for cache keys, URLs, and PDF metadata
    """
    if not auditor_sub:
        raise ValueError("auditor_sub is required for watermark_id")
    if not engagement_id:
        raise ValueError("engagement_id is required for watermark_id")
    digest = hashlib.sha256(f"{auditor_sub}|{engagement_id}".encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).decode("ascii").rstrip("=")


def compute_cache_key(
    *,
    component: str,
    document_id: str,
    user_role: str,
    watermark_id: str | None,
    version_or_etag: str | None,
) -> str:
    """Cache key formula per AMD-13 §Caching."""
    raw = (
        f"{component}:{document_id}:{user_role}:"
        f"{watermark_id or 'none'}:{version_or_etag or 'noetag'}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class CacheEntry:
    pdf_bytes: bytes
    content_type: str = "application/pdf"
    metadata: dict[str, Any] = field(default_factory=dict)


class PdfCache:
    """In-process PDF cache with TTL + LRU eviction.

    Thread-safe (all mutations behind a single lock). Use one instance per
    process; the FastAPI app constructs it during PdfService init.
    """

    def __init__(
        self,
        *,
        ttl_s: int = DEFAULT_TTL_S,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        if ttl_s <= 0:
            raise ValueError("ttl_s must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._ttl_s = ttl_s
        self._max_entries = max_entries
        self._store: TTLCache[str, CacheEntry] = TTLCache(
            maxsize=max_entries, ttl=ttl_s
        )
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> CacheEntry | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            self._hits += 1
            return entry

    def put(self, key: str, entry: CacheEntry) -> None:
        with self._lock:
            self._store[key] = entry

    def invalidate(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def invalidate_all(self) -> int:
        with self._lock:
            n = len(self._store)
            self._store.clear()
            return n

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "hits": self._hits,
                "misses": self._misses,
                "size": len(self._store),
                "max_size": self._max_entries,
                "ttl_s": self._ttl_s,
            }

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._store

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)


__all__ = [
    "PdfCache",
    "CacheEntry",
    "compute_cache_key",
    "compute_watermark_id",
    "DEFAULT_TTL_S",
    "DEFAULT_MAX_ENTRIES",
]
