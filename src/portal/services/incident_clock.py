"""Incident notification countdown — REQ-CPL-016 (NY DFS Part 500 72h clock).

Pure functions; no I/O. Used by the detail template and the optional worker
that emits escalation alerts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

NOTIFICATION_DEADLINE = timedelta(hours=72)
IncidentBand = Literal["red", "amber", "green", "overdue"]


def remaining_to_deadline(
    triggered_at: datetime, now: datetime | None = None
) -> timedelta:
    return (triggered_at + NOTIFICATION_DEADLINE) - (now or datetime.now(UTC))


def band(triggered_at: datetime, now: datetime | None = None) -> IncidentBand:
    rem = remaining_to_deadline(triggered_at, now)
    if rem.total_seconds() <= 0:
        return "overdue"
    if rem <= timedelta(hours=6):
        return "red"
    if rem <= timedelta(hours=24):
        return "amber"
    return "green"


def format_remaining(triggered_at: datetime, now: datetime | None = None) -> str:
    """Human-readable HH:MM:SS countdown for the live banner."""
    rem = remaining_to_deadline(triggered_at, now)
    if rem.total_seconds() <= 0:
        return "OVERDUE"
    secs = int(rem.total_seconds())
    h, rem_s = divmod(secs, 3600)
    m, s = divmod(rem_s, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


__all__ = ["remaining_to_deadline", "band", "format_remaining", "NOTIFICATION_DEADLINE"]
