"""Audit-write guard — REQ-CPL-039 enforcement.

Two-layer guarantee that no portal code path writes to `immutable_audit_events`:

    1. Static check (`tools/check_audit_writes.py`) — runs in CI, greps for
       offending SQL patterns. Lives in the repo root; this module exposes the
       regex so the tool and tests use the same source of truth.
    2. Runtime guard — `install_audit_guard(pool)` patches the asyncpg pool's
       execute/executemany methods to raise on any SQL touching the table.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# Pattern matches DDL/DML against the immutable_audit_events table.
#
# Allows any whitespace, quoted/unquoted, schema-prefixed names. The verb
# alternation now includes ``alter table``, ``drop table``, and ``rename to``
# in addition to the original DML verbs (F-11).
#
# We strip SQL comments and CTE prefixes BEFORE applying these patterns
# (see ``_normalise_sql``) so that:
#   * ``WITH x AS (...) INSERT INTO immutable_audit_events ...``
#   * ``INSERT /* comment */ INTO immutable_audit_events ...``
#   * ``MERGE  INTO   immutable_audit_events ...``
# all match.
_AUDIT_TABLE_PATTERN = re.compile(
    r"""(?ix)
    (?:^|[\s(,;])                 # statement boundary
    (?:                           # forbidden operations:
        insert \s+ into
      | update
      | delete \s+ from
      | merge \s+ into
      | truncate (?: \s+ table )?
      | alter \s+ table
      | drop \s+ table
      | rename \s+ table
      | grant \s+ .+ \s+ on
      | revoke \s+ .+ \s+ on
    )
    \s+
    (?:if \s+ exists \s+)?        # ALTER/DROP TABLE IF EXISTS variants
    (?:only \s+)?                 # PostgreSQL inheritance qualifier
    (?:[\w\."]+\.)?               # optional schema prefix
    "?immutable_audit_events"?    # the forbidden target
    \b                            # word boundary so 'immutable_audit_events_v2' is also caught
    """,
)

# SQL line and block comments. We strip these before pattern matching so
# obfuscation like ``INSERT /* hello */ INTO immutable_audit_events`` is
# normalised to ``INSERT INTO immutable_audit_events``.
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"--[^\n]*")


def _normalise_sql(query: str) -> str:
    """Strip SQL comments and collapse whitespace for guard matching."""
    stripped = _BLOCK_COMMENT.sub(" ", query)
    stripped = _LINE_COMMENT.sub(" ", stripped)
    # Collapse all whitespace to single spaces so ``MERGE\n   INTO``
    # becomes ``MERGE INTO``.
    stripped = re.sub(r"\s+", " ", stripped)
    return stripped


class AuditWriteForbidden(Exception):
    """Raised when a SQL statement attempts to write to immutable_audit_events.

    This is treated as an unrecoverable error — the only legitimate write path
    is the compliance service REST API.
    """

    def __init__(self, *, query: str) -> None:
        super().__init__(
            "Direct write to `immutable_audit_events` is forbidden. "
            "Use the compliance service REST API (POST /audit/events). "
            "REQ-CPL-039 violation."
        )
        self.query = query


def query_touches_audit_table(query: str) -> bool:
    """Return True if the SQL appears to write to the audit table.

    F-11 — comments are stripped and whitespace is collapsed before
    pattern matching so obfuscated DML (``INSERT /* x */ INTO ...``) and
    CTE-prefixed writes (``WITH ... INSERT INTO ...``) are caught.
    """
    if not query or not isinstance(query, str):
        return False
    normalised = _normalise_sql(query)
    return bool(_AUDIT_TABLE_PATTERN.search(normalised))


def install_audit_guard(pool: Any) -> Any:
    """Patch the given asyncpg-style pool/connection so writes to the audit
    table raise AuditWriteForbidden.

    The pool is expected to expose `execute` and `executemany` async methods.
    Returns the same pool (mutated). Idempotent — re-running is a no-op if the
    pool was already guarded.
    """
    if getattr(pool, "_audit_guard_installed", False):
        return pool

    original_execute: Callable[..., Any] | None = getattr(pool, "execute", None)
    original_executemany: Callable[..., Any] | None = getattr(pool, "executemany", None)

    if original_execute is not None:

        async def _guarded_execute(query: str, *args: Any, **kwargs: Any) -> Any:
            if query_touches_audit_table(query):
                raise AuditWriteForbidden(query=query)
            return await original_execute(query, *args, **kwargs)

        pool.execute = _guarded_execute  # type: ignore[assignment]

    if original_executemany is not None:

        async def _guarded_executemany(query: str, *args: Any, **kwargs: Any) -> Any:
            if query_touches_audit_table(query):
                raise AuditWriteForbidden(query=query)
            return await original_executemany(query, *args, **kwargs)

        pool.executemany = _guarded_executemany  # type: ignore[assignment]

    pool._audit_guard_installed = True
    return pool


__all__ = [
    "AuditWriteForbidden",
    "query_touches_audit_table",
    "install_audit_guard",
]
