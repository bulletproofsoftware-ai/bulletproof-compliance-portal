"""Structured JSON logging with PII redaction.

Implements REQ-CPL-001 logging requirements plus AMD-17 (CISO M-8 / GDPR Art 32):
subject PII MUST be redacted in every log line, at any nesting depth, before
the line is rendered.

Use `get_logger(__name__)` to obtain a structlog logger anywhere in the codebase.
NEVER use `print()` and NEVER use bare `logging.getLogger` in application code —
the redaction processor only applies to structlog's pipeline.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Mapping

import structlog
from structlog.types import EventDict, Processor

# ─── Redaction allowlist ─────────────────────────────────────────────────────
# Per AMD-17, subject PII MUST be redacted. Existing transport/auth secrets
# remain redacted as well. Match is case-insensitive on the field name at any
# nesting depth.
REDACTED_FIELDS: frozenset[str] = frozenset(
    {
        # Auth/transport secrets
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "cookie",
        "session_id",
        "client_secret",
        "api_key",
        "api_token",
        # Subject PII (AMD-17 — DSR / WI-08 / WI-09)
        "subject_email",
        "subject_name",
        "subject_phone",
        "subject_address",
        "dob",
        "ssn",
        "tax_id",
    }
)

REDACTED_VALUE = "[REDACTED]"


def _redact_pii(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Recursively replace REDACTED_FIELDS values with [REDACTED].

    Walks dicts (any depth) and lists. Keys are matched case-insensitively.
    """

    def walk(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            return {
                k: (REDACTED_VALUE if str(k).lower() in REDACTED_FIELDS else walk(v))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [walk(x) for x in obj]
        if isinstance(obj, tuple):
            return tuple(walk(x) for x in obj)
        return obj

    redacted = walk(event_dict)
    # walk() returns a dict when given a dict; appease mypy by asserting type
    assert isinstance(redacted, dict)
    return redacted


def _add_app_context(_logger: Any, _name: str, event_dict: EventDict) -> EventDict:
    """Attach static app metadata to every log line."""
    event_dict.setdefault("app", "compliance-portal")
    return event_dict


def configure_logging(
    *,
    level: str = "INFO",
    json_output: bool = True,
    extra_processors: list[Processor] | None = None,
) -> None:
    """Configure stdlib logging + structlog pipeline.

    Args:
        level: log level name.
        json_output: if True, emit JSON; else, render with the dev console renderer.
        extra_processors: additional processors inserted BEFORE the renderer
            (after redaction).
    """
    level_int = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level_int,
        force=True,
    )

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)

    pre_chain: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        timestamper,
        _add_app_context,
        _redact_pii,  # MUST run before renderer
    ]

    if extra_processors:
        pre_chain.extend(extra_processors)

    renderer: Processor
    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    processors: list[Processor] = [
        *pre_chain,
        renderer,
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structlog logger bound to the given name."""
    return structlog.get_logger(name) if name else structlog.get_logger()


def bind_request_context(*, request_id: str, **kwargs: Any) -> None:
    """Bind per-request context vars (request_id, user_id, etc.) for the duration
    of the current async task."""
    structlog.contextvars.bind_contextvars(request_id=request_id, **kwargs)


def clear_request_context() -> None:
    """Clear context vars (call at end of request)."""
    structlog.contextvars.clear_contextvars()


__all__ = [
    "REDACTED_FIELDS",
    "REDACTED_VALUE",
    "configure_logging",
    "get_logger",
    "bind_request_context",
    "clear_request_context",
]
