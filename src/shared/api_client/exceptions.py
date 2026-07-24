"""Typed exceptions for the compliance API client (WI-03)."""

from __future__ import annotations


class ComplianceClientError(Exception):
    """Base exception for all compliance-client failures."""

    def __init__(
        self,
        *,
        status: int | None,
        code: str,
        message: str,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(status={self.status}, code={self.code!r}, "
            f"request_id={self.request_id!r}, message={self.message!r})"
        )


class NotFoundError(ComplianceClientError):
    """HTTP 404."""


class ConflictError(ComplianceClientError):
    """HTTP 409 — typically SoD violation per REQ-CPL-009."""


class ScopeViolationError(ComplianceClientError):
    """HTTP 403 with code=scope_violation — auditor exceeded engagement scope."""


class AuthenticationError(ComplianceClientError):
    """HTTP 401 — missing/invalid bearer or mTLS rejection."""


class ServiceUnavailableError(ComplianceClientError):
    """HTTP 503 or circuit breaker open — fail fast."""


class ValidationError(ComplianceClientError):
    """HTTP 422 — request payload rejected by server validation."""


class UnexpectedRedirectError(ComplianceClientError):
    """AMD-25 — server replied with a redirect; client refuses to follow."""


__all__ = [
    "ComplianceClientError",
    "NotFoundError",
    "ConflictError",
    "ScopeViolationError",
    "AuthenticationError",
    "ServiceUnavailableError",
    "ValidationError",
    "UnexpectedRedirectError",
]
