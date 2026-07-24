"""Retry helpers — exponential backoff with jitter."""

from __future__ import annotations

import random


def backoff_delays(
    *,
    max_attempts: int,
    base_ms: float = 100.0,
    factor: float = 4.0,
    cap_ms: float = 1600.0,
    jitter: float = 0.25,
) -> list[float]:
    """Return per-attempt sleep durations in seconds.

    For max_attempts=3 this yields ~[0.1, 0.4, 1.6] with jitter.

    The first element is the delay BEFORE retry attempt 2 (i.e., the post-attempt-1
    sleep). attempts is 1-indexed in the caller.
    """
    delays: list[float] = []
    val = base_ms
    for _ in range(max_attempts - 1):
        # apply jitter: ± jitter * val
        spread = val * jitter
        delays.append(max(0.0, random.uniform(val - spread, val + spread)) / 1000.0)
        val = min(val * factor, cap_ms)
    return delays


def is_retryable_status(status_code: int) -> bool:
    """Server-side errors that warrant a retry. Never retry 4xx."""
    return 500 <= status_code <= 599


__all__ = ["backoff_delays", "is_retryable_status"]
