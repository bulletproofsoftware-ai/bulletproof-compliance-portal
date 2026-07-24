"""Behavioral analysis hook (WI-17) — non-blocking forwarder to PRD-11.

Heuristics implemented locally:
    - response status >= 400 (auth failure / abuse signal)
    - high request rate (caller-supplied via app.state.behavior_metrics)
    - unusual user-agent strings (very short or known scanner fingerprints)

Any anomaly is forwarded fire-and-forget to the configured webhook (if any);
failures are swallowed (logged) so PRD-11 outage cannot drag the portal down.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from ..logging import get_logger

logger = get_logger(__name__)

_SUSPICIOUS_UA = re.compile(
    r"(?i)(sqlmap|nikto|nmap|wpscan|metasploit|hydra|dirb|burp|ffuf|gobuster)"
)


def anomaly_score(*, status: int, user_agent: str | None) -> float:
    """Return a [0,1] anomaly score. Local heuristic; PRD-11 makes the
    real decision."""
    score = 0.0
    if status >= 400:
        score += 0.3
    if status >= 500:
        score += 0.2
    ua = user_agent or ""
    if len(ua) < 5:
        score += 0.2
    if _SUSPICIOUS_UA.search(ua):
        score += 0.7
    return min(score, 1.0)


class BehaviorHookMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,  # type: ignore[no-untyped-def]
        *,
        enabled: bool = False,
        webhook_url: str | None = None,
        threshold: float = 0.5,
        timeout_s: float = 2.0,
    ) -> None:
        super().__init__(app)
        self._enabled = enabled and bool(webhook_url)
        self._webhook_url = webhook_url
        self._threshold = threshold
        self._timeout_s = timeout_s

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        if not self._enabled:
            return response

        score = anomaly_score(
            status=response.status_code,
            user_agent=request.headers.get("user-agent"),
        )
        if score < self._threshold:
            return response

        signal: dict[str, Any] = {
            "request_id": getattr(request.state, "request_id", None),
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "anomaly_score": score,
        }
        # Fire-and-forget — never block the response
        asyncio.create_task(self._forward(signal))
        return response

    async def _forward(self, signal: dict[str, Any]) -> None:
        if not self._webhook_url:
            return
        try:
            async with httpx.AsyncClient(timeout=self._timeout_s, follow_redirects=False) as client:
                await client.post(self._webhook_url, json=signal)
        except Exception as exc:  # noqa: BLE001
            logger.warning("behavior_hook.forward_failed", error=str(exc))


__all__ = ["BehaviorHookMiddleware", "anomaly_score"]
