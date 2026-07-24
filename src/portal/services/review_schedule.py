"""Model card review reminder scheduling per REQ-CPL-020.

Pure functions; no I/O. The reminder worker reads model cards from the service
and uses these helpers to determine which reminders should fire today.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

ReminderWindow = Literal["30d", "7d", "0d"]


@dataclass(frozen=True)
class Reminder:
    window: ReminderWindow
    fires_at: datetime


def upcoming_reminders(
    next_review_date: datetime, now: datetime | None = None
) -> list[Reminder]:
    """Returns the three reminder anchors (30d/7d/0d) for a given next-review-date.

    The `now` parameter is unused at this layer (it's used by callers to filter)
    — kept in the signature for symmetry with the WI-11 spec.
    """
    return [
        Reminder("30d", next_review_date - timedelta(days=30)),
        Reminder("7d", next_review_date - timedelta(days=7)),
        Reminder("0d", next_review_date),
    ]


def reminders_due(
    next_review_date: datetime, now: datetime | None = None, window_hours: int = 24
) -> list[Reminder]:
    """Filters `upcoming_reminders` to those that should fire within the given
    window centered on `now`. Default window is 24h (the worker runs daily)."""
    now = now or datetime.now(UTC)
    out = []
    for r in upcoming_reminders(next_review_date, now=now):
        delta = (r.fires_at - now).total_seconds()
        if -window_hours * 3600 <= delta <= window_hours * 3600:
            out.append(r)
    return out


def review_band(
    next_review_date: datetime, now: datetime | None = None
) -> Literal["red", "amber", "green", "overdue"]:
    """Display band for the registry list."""
    now = now or datetime.now(UTC)
    days = (next_review_date - now).total_seconds() / 86400.0
    if days < 0:
        return "overdue"
    if days <= 7:
        return "red"
    if days <= 30:
        return "amber"
    return "green"


__all__ = ["Reminder", "upcoming_reminders", "reminders_due", "review_band"]
