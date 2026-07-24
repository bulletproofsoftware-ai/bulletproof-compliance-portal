"""Circuit breaker primitive for the compliance API client.

States:
    CLOSED      — requests flow normally; failures counted in a sliding window
    OPEN        — fail fast for `cooldown_s` seconds
    HALF_OPEN   — allow ONE probe request; success → CLOSED, failure → OPEN
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from enum import StrEnum


class CircuitBreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Async-safe circuit breaker."""

    def __init__(
        self,
        *,
        failure_threshold: int = 5,
        window_s: float = 30.0,
        cooldown_s: float = 60.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self._failures: deque[float] = deque()
        self._state: CircuitBreakerState = CircuitBreakerState.CLOSED
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()
        self._half_open_in_flight = False

    @property
    def state(self) -> CircuitBreakerState:
        return self._state

    async def can_request(self) -> bool:
        """Returns True if the request should be attempted; False = fail fast."""
        async with self._lock:
            now = time.monotonic()
            self._prune(now)

            if self._state is CircuitBreakerState.CLOSED:
                return True

            if self._state is CircuitBreakerState.OPEN:
                if now - self._opened_at >= self.cooldown_s:
                    self._state = CircuitBreakerState.HALF_OPEN
                    self._half_open_in_flight = True
                    return True
                return False

            # HALF_OPEN — only one probe in flight
            if self._half_open_in_flight:
                return False
            self._half_open_in_flight = True
            return True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures.clear()
            if self._state in (CircuitBreakerState.HALF_OPEN, CircuitBreakerState.OPEN):
                self._state = CircuitBreakerState.CLOSED
            self._half_open_in_flight = False

    async def record_failure(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._prune(now)
            self._failures.append(now)
            if self._state is CircuitBreakerState.HALF_OPEN:
                self._state = CircuitBreakerState.OPEN
                self._opened_at = now
                self._half_open_in_flight = False
                self._failures.clear()
                return
            if (
                self._state is CircuitBreakerState.CLOSED
                and len(self._failures) >= self.failure_threshold
            ):
                self._state = CircuitBreakerState.OPEN
                self._opened_at = now
                self._half_open_in_flight = False
                self._failures.clear()

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_s
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()


__all__ = ["CircuitBreaker", "CircuitBreakerState"]
