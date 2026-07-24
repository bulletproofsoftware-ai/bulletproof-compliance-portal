"""Health (`/healthz`) and readiness (`/readyz`) endpoints (WI-01)."""

from __future__ import annotations

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def healthz() -> JSONResponse:
    """Liveness — must NEVER depend on downstream services."""
    return JSONResponse({"status": "ok"})


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    """Readiness — checks compliance API + circuit breaker state.

    Returns 200 with status=ok when all checks pass; 503 otherwise.
    """
    compliance_client = getattr(request.app.state, "compliance_client", None)
    breaker_state = "closed"
    compliance_ok = True

    if compliance_client is not None:
        breaker_state = str(compliance_client.circuit_breaker_state)
        compliance_ok = await compliance_client.health()

    body = {
        "status": "ok" if compliance_ok else "degraded",
        "compliance_api": compliance_ok,
        "compliance_circuit": breaker_state,
    }
    code = status.HTTP_200_OK if compliance_ok else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(body, status_code=code)
