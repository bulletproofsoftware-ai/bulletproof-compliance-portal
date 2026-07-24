"""DSR SLA computation per REQ-CPL-013 (30-day countdown + escalation bands).

Pure functions; no I/O. Used by both the queue router and the worker that
emits 7d/3d/1d escalation notifications.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

SlaBand = Literal["red", "amber", "yellow", "green", "overdue"]

DSR_SLA_DAYS = 30


def remaining_days(submitted_at: datetime, now: datetime | None = None) -> float:
    """Fractional days remaining before the 30-day SLA deadline.

    Negative when overdue. Always returns a float to support sub-day precision
    rendering (the template formats as integer days for the queue badge).
    """
    now = now or datetime.now(UTC)
    deadline = submitted_at + timedelta(days=DSR_SLA_DAYS)
    return (deadline - now).total_seconds() / 86400.0


def sla_band(rem_days: float) -> SlaBand:
    """Map remaining days to a UI band. Boundaries are inclusive on the
    larger side (e.g., exactly 7 days → yellow, exactly 3 → amber).

    Bands per REQ-CPL-013:
        overdue   rem_days < 0
        red       0 <= rem_days <= 1
        amber     1 < rem_days <= 3
        yellow    3 < rem_days <= 7
        green     rem_days > 7
    """
    if rem_days < 0:
        return "overdue"
    if rem_days <= 1:
        return "red"
    if rem_days <= 3:
        return "amber"
    if rem_days <= 7:
        return "yellow"
    return "green"


def escalation_due(rem_days: float, threshold_days: int) -> bool:
    """Whether an escalation at the given threshold (7/3/1) should fire."""
    if threshold_days not in {7, 3, 1}:
        raise ValueError(f"escalation threshold must be one of 7/3/1, got {threshold_days}")
    # Fire when remaining drops at or below the threshold but is still positive.
    return 0 < rem_days <= threshold_days


__all__ = ["remaining_days", "sla_band", "escalation_due", "DSR_SLA_DAYS", "SlaBand"]
