"""ComplianceClient — async HTTP client to the PRD-18 compliance service.

Implements WI-03 with all CISO amendments:

    AMD-10  mTLS support (or IP allowlist via service config)
    AMD-25  follow_redirects=False — refuses to follow any redirect

Architectural rule: this is the only place in the portal codebase that may
construct `httpx.AsyncClient`. CI lint MUST enforce this.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import httpx

_UA = "compliance-portal/0.1"

from .circuit_breaker import CircuitBreaker, CircuitBreakerState
from .exceptions import (
    AuthenticationError,
    ComplianceClientError,
    ConflictError,
    NotFoundError,
    ScopeViolationError,
    ServiceUnavailableError,
    UnexpectedRedirectError,
    ValidationError,
)
from .models import (
    AgentEconomicsList,
    AuditEvent,
    AuditEventList,
    AuditRecordResult,
    AuditorEngagement,
    AuditorEngagementList,
    ComplianceControlDetail,
    ComplianceGapAnalysis,
    ComplianceScores,
    ComplianceTrends,
    DocDiff,
    DocVersionList,
    DsrDeliveryToken,
    DsrEvidenceJob,
    DsrPublicStatus,
    DsrPublicSubmissionResult,
    DsrRequest,
    DsrRequestList,
    DsrTransitionResult,
    EngagementAccessLog,
    EvidenceDiff,
    EvidenceDownload,
    EvidencePackage,
    EvidencePackageList,
    EvidenceSignatureStatus,
    EvidenceVersionList,
    ForecastData,
    GateDecisionReceipt,
    HashChainVerification,
    HumanGate,
    HumanGateList,
    IdentityProofScanResult,
    Incident,
    IncidentList,
    IncidentNote,
    IncidentNotification,
    KnowledgeBatchResult,
    KnowledgeCandidate,
    KnowledgeCandidateList,
    ModelCard,
    ModelCardReview,
    OutcomeKPIs,
    OutcomeSummary,
    ProjectDoc,
    ProjectList,
    ProjectSummary,
    RegulatoryReport,
    RegulatoryReportList,
    ReportDelivery,
    SearchResults,
)
from .retry import backoff_delays, is_retryable_status


class ComplianceClient:
    """Per-request scoped client. The constructor accepts the calling user's
    sub and request_id so the X-On-Behalf-Of and X-Request-ID headers are
    automatically injected on every call."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout_s: float = 10.0,
        ca_bundle: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
        user_sub: str | None = None,
        request_id: str | None = None,
        auditor_scope: dict[str, Any] | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._user_sub = user_sub
        self._request_id = request_id or uuid.uuid4().hex
        self._auditor_scope = auditor_scope
        self._cb = circuit_breaker or CircuitBreaker()

        verify: Any = ca_bundle if ca_bundle else True
        cert: tuple[str, str] | None = (
            (client_cert, client_key) if (client_cert and client_key) else None
        )

        client_kwargs: dict[str, Any] = {
            "base_url": self._base_url,
            "timeout": httpx.Timeout(timeout_s),
            # AMD-25 — never follow redirects (SSRF amplification + auth downgrade)
            "follow_redirects": False,
            "verify": verify,
            "cert": cert,
            "headers": {
                "Authorization": f"Bearer {token}",
                "User-Agent": _UA,
                "Accept": "application/json",
            },
        }
        if transport is not None:
            client_kwargs["transport"] = transport

        self._http = httpx.AsyncClient(**client_kwargs)

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "ComplianceClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # ── Internals ────────────────────────────────────────────────────────────

    @property
    def follow_redirects(self) -> bool:
        """Exposed so the lint test can assert configuration."""
        return self._http.follow_redirects

    @property
    def circuit_breaker_state(self) -> CircuitBreakerState:
        return self._cb.state

    def _common_headers(self) -> dict[str, str]:
        h = {"X-Request-ID": self._request_id}
        if self._user_sub:
            h["X-On-Behalf-Of"] = self._user_sub
        return h

    def _scope_params(self) -> dict[str, Any]:
        if not self._auditor_scope:
            return {}
        s = self._auditor_scope
        params: dict[str, Any] = {}
        if "engagement_id" in s:
            params["engagement_id"] = s["engagement_id"]
        if "date_range_start" in s:
            params["from"] = s["date_range_start"]
        if "date_range_end" in s:
            params["to"] = s["date_range_end"]
        if s.get("allowed_artifact_types"):
            params["artifact_types"] = ",".join(s["allowed_artifact_types"])
        return params

    @staticmethod
    def _idempotency_key(method: str, path: str, user_sub: str | None) -> str:
        seed = f"{method}:{path}:{user_sub or 'anon'}:{uuid.uuid4().hex}"
        return seed[:80]

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        idempotent: bool = True,
        max_attempts: int = 3,
    ) -> httpx.Response:
        """Execute the HTTP request with retry, circuit breaker, redirect guard."""
        # Prove the target is still an internal relative path before anything
        # else happens (CodeQL py/partial-ssrf).
        #
        # Callers build paths by interpolating ids into literals -- there are
        # 40-odd such f-strings in this module, and every id ultimately arrives
        # from a request. Rather than encode at each construction site, the
        # invariant is enforced once here, at the choke point every request
        # passes through. Written inline rather than extracted to a helper so
        # the guard sits in the same function as the httpx call it protects.
        #
        # httpx only joins a URL onto base_url when it is relative, so a value
        # carrying its own authority ("//host/x") would be fetched from that
        # host instead of the compliance service. Query strings always travel
        # via `params`, so a "?" or "#" arriving here means an id smuggled one
        # in. A plain space is legal in a document filename and httpx encodes
        # it; CR/LF are what would break out of the request line.
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"api path must be relative and absolute-rooted: {path!r}")
        if path.startswith("//") or path.startswith("/\\"):
            raise ValueError(f"api path must not carry an authority: {path!r}")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
            raise ValueError("api path must not contain control characters")
        if "?" in path or "#" in path:
            raise ValueError(f"api path must not contain a query or fragment: {path!r}")
        # Interior "/" is legitimate (doc paths are multi-segment); a traversal
        # step is not, and would let one endpoint's id address another.
        if any(seg == ".." for seg in path.split("/")):
            raise ValueError(f"api path must not traverse: {path!r}")

        # Circuit breaker check
        if not await self._cb.can_request():
            raise ServiceUnavailableError(
                status=None,
                code="circuit_open",
                message="circuit breaker is OPEN; failing fast",
                request_id=self._request_id,
            )

        # Auto-merge auditor scope on GETs only (mutations skip — service does scope check)
        merged_params = dict(params or {})
        if method == "GET":
            merged_params = {**self._scope_params(), **merged_params}

        headers = self._common_headers()
        if method != "GET" and idempotent:
            headers["Idempotency-Key"] = self._idempotency_key(method, path, self._user_sub)

        attempts_max = max_attempts if method == "GET" else min(max_attempts, 2)
        delays = backoff_delays(max_attempts=attempts_max)

        last_exc: Exception | None = None
        for attempt in range(attempts_max):
            try:
                response = await self._http.request(
                    method,
                    path,
                    params=merged_params or None,
                    json=json_body,
                    headers=headers,
                )
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                await self._cb.record_failure()
                if attempt + 1 < attempts_max:
                    await asyncio.sleep(delays[attempt])
                    continue
                raise ServiceUnavailableError(
                    status=None,
                    code="connection_error",
                    message=str(exc),
                    request_id=self._request_id,
                ) from exc

            # AMD-25: never auto-follow. If a redirect arrived, fail loudly.
            if response.is_redirect:
                location = response.headers.get("Location", "")
                await self._cb.record_failure()
                raise UnexpectedRedirectError(
                    status=response.status_code,
                    code="unexpected_redirect",
                    message=f"server returned redirect to {location!r}; refusing to follow",
                    request_id=response.headers.get("X-Request-ID") or self._request_id,
                )

            # Retry policy
            if is_retryable_status(response.status_code):
                await self._cb.record_failure()
                if attempt + 1 < attempts_max:
                    await asyncio.sleep(delays[attempt])
                    continue
                raise self._http_error(response)

            # 4xx or 2xx — terminal
            if response.status_code >= 400:
                # don't count 4xx against the breaker; map to typed exception
                if response.status_code in (502, 503, 504):
                    await self._cb.record_failure()
                raise self._http_error(response)

            await self._cb.record_success()
            return response

        # Should not reach
        raise ServiceUnavailableError(
            status=None,
            code="exhausted",
            message=f"retries exhausted: {last_exc}",
            request_id=self._request_id,
        )

    def _http_error(self, response: httpx.Response) -> ComplianceClientError:
        """Map an HTTP error response to a typed exception."""
        request_id = response.headers.get("X-Request-ID") or self._request_id
        try:
            body = response.json()
            code = str(body.get("code") or body.get("error") or "")
            message = str(body.get("message") or body.get("detail") or response.text or "")
        except Exception:  # noqa: BLE001
            code = ""
            message = response.text or ""

        kwargs = {
            "status": response.status_code,
            "code": code or f"http_{response.status_code}",
            "message": message,
            "request_id": request_id,
        }

        if response.status_code == 401:
            return AuthenticationError(**kwargs)
        if response.status_code == 403:
            if code == "scope_violation":
                return ScopeViolationError(**kwargs)
            return ComplianceClientError(**kwargs)
        if response.status_code == 404:
            return NotFoundError(**kwargs)
        if response.status_code == 409:
            return ConflictError(**kwargs)
        if response.status_code == 422:
            return ValidationError(**kwargs)
        if 500 <= response.status_code <= 599:
            return ServiceUnavailableError(**kwargs)
        return ComplianceClientError(**kwargs)

    # ── Endpoints — selected (per WI-03) ─────────────────────────────────────
    # The full PRD-18 contract is a moving target; these methods cover the
    # foundation needs. Component specs (WI-04+) extend this surface as needed.

    # Audit
    async def list_audit_events(self, **filters: Any) -> AuditEventList:
        r = await self._request("GET", "/audit/events", params=filters)
        return AuditEventList.model_validate(r.json())

    async def get_audit_event(self, event_id: str) -> AuditEvent:
        r = await self._request("GET", f"/audit/events/{event_id}")
        return AuditEvent.model_validate(r.json())

    async def verify_hash_chain(self, from_id: int, to_id: int) -> HashChainVerification:
        r = await self._request("GET", "/audit/verify", params={"from": from_id, "to": to_id})
        return HashChainVerification.model_validate(r.json())

    async def record_audit_event(
        self,
        *,
        audit_type: str,
        user_id: str | None = None,
        classification: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecordResult:
        body = {
            "audit_type": audit_type,
            "user_id": user_id,
            "classification": classification,
            "payload": payload or {},
            "ts": time.time(),
        }
        r = await self._request("POST", "/audit/events", json_body=body)
        return AuditRecordResult.model_validate(r.json())

    # Evidence
    async def list_evidence_packages(self, **filters: Any) -> EvidencePackageList:
        r = await self._request("GET", "/evidence", params=filters)
        return EvidencePackageList.model_validate(r.json())

    async def get_evidence_package(self, pkg_id: str) -> EvidencePackage:
        r = await self._request("GET", f"/evidence/{pkg_id}")
        return EvidencePackage.model_validate(r.json())

    async def list_evidence_versions(self, pkg_id: str) -> EvidenceVersionList:
        """REQ-CPL-007 — version history per package."""
        r = await self._request("GET", f"/evidence/{pkg_id}/versions")
        return EvidenceVersionList.model_validate(r.json())

    async def get_evidence_diff(
        self, pkg_id: str, *, from_version: str, to_version: str
    ) -> EvidenceDiff:
        """REQ-CPL-007 — text diff between two versions (server-computed)."""
        r = await self._request(
            "GET",
            f"/evidence/{pkg_id}/diff",
            params={"from": from_version, "to": to_version},
        )
        return EvidenceDiff.model_validate(r.json())

    async def verify_evidence_signature(
        self, pkg_id: str, *, version: str | None = None
    ) -> EvidenceSignatureStatus:
        """REQ-CPL-007 — Ed25519 signature verification (service-side)."""
        params: dict[str, Any] = {}
        if version is not None:
            params["version"] = version
        r = await self._request("GET", f"/evidence/{pkg_id}/verify", params=params)
        return EvidenceSignatureStatus.model_validate(r.json())

    async def get_evidence_download_metadata(
        self, pkg_id: str, *, version: str | None = None, purpose: str | None = None
    ) -> EvidenceDownload:
        """REQ-CPL-007 — initiate a download; the service records the audit event
        with the supplied purpose."""
        body: dict[str, Any] = {}
        if version is not None:
            body["version"] = version
        if purpose is not None:
            body["purpose"] = purpose
        r = await self._request(
            "POST", f"/evidence/{pkg_id}/download", json_body=body, idempotent=True
        )
        return EvidenceDownload.model_validate(r.json())

    # Human Gates
    async def list_human_gates(self, **filters: Any) -> HumanGateList:
        r = await self._request("GET", "/gates", params=filters)
        return HumanGateList.model_validate(r.json())

    async def get_human_gate(self, gate_id: str) -> HumanGate:
        r = await self._request("GET", f"/gates/{gate_id}")
        return HumanGate.model_validate(r.json())

    async def decide_human_gate(
        self,
        gate_id: str,
        *,
        decision: str,  # approve | deny | escalate
        rationale: str,
        decision_nonce: str | None = None,
        escalate_to_role: str | None = None,
    ) -> GateDecisionReceipt:
        """REQ-CPL-009/010/011 — submit decision; service signs receipt and
        enforces SoD (REQ-CPL-010) authoritatively. Portal pre-checks too."""
        body: dict[str, Any] = {"decision": decision, "rationale": rationale}
        if decision_nonce is not None:
            body["decision_nonce"] = decision_nonce
        if escalate_to_role is not None:
            body["escalate_to_role"] = escalate_to_role
        r = await self._request(
            "POST", f"/gates/{gate_id}/decide", json_body=body, idempotent=True
        )
        return GateDecisionReceipt.model_validate(r.json())

    async def get_gate_receipt(self, gate_id: str) -> GateDecisionReceipt:
        """Idempotent re-fetch of the signed receipt for a decided gate."""
        r = await self._request("GET", f"/gates/{gate_id}/receipt")
        return GateDecisionReceipt.model_validate(r.json())

    # Auditor Engagements (REQ-CPL-033/034/035)
    async def list_engagements(self, **filters: Any) -> AuditorEngagementList:
        r = await self._request("GET", "/engagements", params=filters)
        return AuditorEngagementList.model_validate(r.json())

    async def get_engagement(self, engagement_id: str) -> AuditorEngagement:
        r = await self._request("GET", f"/engagements/{engagement_id}")
        return AuditorEngagement.model_validate(r.json())

    async def create_engagement(
        self,
        *,
        auditor_email: str,
        engagement_start: str,  # ISO-8601
        engagement_end: str,
        date_range_start: str,
        date_range_end: str,
        allowed_artifact_types: list[str],
        allowed_project_ids: list[str] | None = None,
    ) -> AuditorEngagement:
        body: dict[str, Any] = {
            "auditor_email": auditor_email,
            "engagement_start": engagement_start,
            "engagement_end": engagement_end,
            "date_range_start": date_range_start,
            "date_range_end": date_range_end,
            "allowed_artifact_types": allowed_artifact_types,
            "allowed_project_ids": allowed_project_ids,
        }
        r = await self._request("POST", "/engagements", json_body=body, idempotent=True)
        return AuditorEngagement.model_validate(r.json())

    async def revoke_engagement(
        self, engagement_id: str, *, reason: str
    ) -> AuditorEngagement:
        """REQ-CPL-034 — instant revocation."""
        body = {"reason": reason}
        r = await self._request(
            "POST",
            f"/engagements/{engagement_id}/revoke",
            json_body=body,
            idempotent=True,
        )
        return AuditorEngagement.model_validate(r.json())

    async def get_engagement_access_log(
        self, engagement_id: str, **filters: Any
    ) -> EngagementAccessLog:
        r = await self._request(
            "GET", f"/engagements/{engagement_id}/access-log", params=filters
        )
        return EngagementAccessLog.model_validate(r.json())

    async def log_engagement_access(
        self,
        engagement_id: str,
        *,
        artifact_type: str,
        artifact_id: str,
        action: str = "view",
    ) -> AuditRecordResult:
        """REQ-CPL-034 — record an artifact view by the auditor.

        Implemented in terms of `record_audit_event` so that PRD-18 isn't
        required to ship a dedicated /engagements/{id}/access-log POST. The
        `audit_type=auditor.artifact.viewed` carries engagement_id + artifact in
        the payload so the service can index by engagement on the read path
        (`get_engagement_access_log`).
        """
        return await self.record_audit_event(
            audit_type=f"auditor.artifact.{action}",
            user_id=self._user_sub,
            classification="confidential",
            payload={
                "engagement_id": engagement_id,
                "artifact_type": artifact_type,
                "artifact_id": artifact_id,
                "action": action,
            },
        )

    # ── DSR — Internal (WI-08) ──────────────────────────────────────────────
    async def list_dsr_requests(self, **filters: Any) -> DsrRequestList:
        r = await self._request("GET", "/dsr", params=filters)
        return DsrRequestList.model_validate(r.json())

    async def get_dsr_request(self, req_id: str) -> DsrRequest:
        r = await self._request("GET", f"/dsr/{req_id}")
        return DsrRequest.model_validate(r.json())

    async def submit_dsr_request(
        self,
        *,
        request_type: str,
        subject_name: str | None = None,
        subject_email: str | None = None,
        subject_address: str | None = None,
        subject_dob: str | None = None,
        description: str | None = None,
        source: str = "internal",
        identity_proof_id: str | None = None,
        notes: str | None = None,
    ) -> DsrRequest:
        """REQ-CPL-012 — submit a DSR. `source=public` for self-service, else internal."""
        body: dict[str, Any] = {
            "request_type": request_type,
            "source": source,
        }
        if subject_name is not None:
            body["subject_name"] = subject_name
        if subject_email is not None:
            body["subject_email"] = subject_email
        if subject_address is not None:
            body["subject_address"] = subject_address
        if subject_dob is not None:
            body["subject_dob"] = subject_dob
        if description is not None:
            body["description"] = description
        if identity_proof_id is not None:
            body["identity_proof_id"] = identity_proof_id
        if notes is not None:
            body["notes"] = notes
        r = await self._request("POST", "/dsr", json_body=body, idempotent=True)
        return DsrRequest.model_validate(r.json())

    async def transition_dsr_status(
        self,
        req_id: str,
        *,
        to_status: str,
        notes: str | None = None,
        rejection_reason: str | None = None,
        verification_method: str | None = None,
        acknowledgment_method: str | None = None,
        acknowledged_at: str | None = None,
    ) -> DsrTransitionResult:
        """REQ-CPL-014 — state machine transition.

        Service authoritatively enforces valid transitions, SoD (AMD-01), and
        atomically invalidates outstanding delivery tokens on close (AMD-12).
        """
        body: dict[str, Any] = {"to_status": to_status}
        if notes is not None:
            body["notes"] = notes
        if rejection_reason is not None:
            body["rejection_reason"] = rejection_reason
        if verification_method is not None:
            body["verification_method"] = verification_method
        if acknowledgment_method is not None:
            body["acknowledgment_method"] = acknowledgment_method
        if acknowledged_at is not None:
            body["acknowledged_at"] = acknowledged_at
        r = await self._request(
            "POST", f"/dsr/{req_id}/transition", json_body=body, idempotent=True
        )
        return DsrTransitionResult.model_validate(r.json())

    async def generate_dsr_evidence(self, req_id: str) -> DsrEvidenceJob:
        """REQ-CPL-015 — start filtered evidence package generation.

        Returns either job (202) or evidence package id (200). Service may
        return either form; the response model accommodates both shapes.
        """
        r = await self._request(
            "POST", f"/dsr/{req_id}/generate-evidence", json_body={}, idempotent=True
        )
        return DsrEvidenceJob.model_validate(r.json())

    async def deliver_dsr(
        self, req_id: str, *, package_id: str, version: str = "v1"
    ) -> DsrDeliveryToken:
        """Issue a one-time delivery token bound to (req_id, package_id, version).

        AMD-16: the compliance service marks the token used atomically (CAS).
        AMD-12: tokens issued here are invalidated when the DSR is closed.
        """
        body = {"package_id": package_id, "version": version}
        r = await self._request(
            "POST", f"/dsr/{req_id}/deliver", json_body=body, idempotent=True
        )
        return DsrDeliveryToken.model_validate(r.json())

    async def close_dsr(
        self,
        req_id: str,
        *,
        acknowledged_at: str | None = None,
        acknowledgment_method: str = "email",
        notes: str | None = None,
    ) -> DsrTransitionResult:
        """Close the DSR; AMD-12: invalidates ALL outstanding delivery tokens."""
        return await self.transition_dsr_status(
            req_id,
            to_status="closed",
            acknowledged_at=acknowledged_at,
            acknowledgment_method=acknowledgment_method,
            notes=notes,
        )

    # ── DSR — Public (WI-09) ────────────────────────────────────────────────
    async def submit_public_dsr(
        self,
        *,
        request_type: str,
        subject_name: str,
        subject_email: str,
        description: str | None = None,
        identity_proof_id: str | None = None,
        subject_address: str | None = None,
        subject_dob: str | None = None,
    ) -> DsrPublicSubmissionResult:
        """AMD-05 ACL: SUBMIT capability."""
        body: dict[str, Any] = {
            "request_type": request_type,
            "subject_name": subject_name,
            "subject_email": subject_email,
            "source": "public",
        }
        if description is not None:
            body["description"] = description
        if identity_proof_id is not None:
            body["identity_proof_id"] = identity_proof_id
        if subject_address is not None:
            body["subject_address"] = subject_address
        if subject_dob is not None:
            body["subject_dob"] = subject_dob
        r = await self._request("POST", "/dsr", json_body=body, idempotent=True)
        return DsrPublicSubmissionResult.model_validate(r.json())

    async def check_dsr_status_by_token(
        self, *, reference: str, email: str
    ) -> DsrPublicStatus:
        """AMD-05 ACL: STATUS_CHECK capability — returns sanitized payload only."""
        body = {"reference": reference, "email": email}
        r = await self._request(
            "POST", "/dsr/public/status", json_body=body, idempotent=True
        )
        return DsrPublicStatus.model_validate(r.json())

    async def upload_identity_proof(
        self,
        *,
        reference: str,
        email: str,
        filename: str,
        content_type: str,
        file_bytes: bytes,
    ) -> IdentityProofScanResult:
        """AMD-05 ACL: IDENTITY_UPLOAD capability + AMD-26 malware scan.

        Streams to compliance service; service holds in quarantine until scan
        completes. Returns scan verdict; portal returns 422 if not clean.
        """
        # Multipart upload — AMD-11: portal enforces 5MB cap upstream
        files = {"file": (filename, file_bytes, content_type)}
        data = {"reference": reference, "email": email}
        # Bypass _request because we need multipart; use raw http but preserve
        # all the safety properties (no redirects, headers, etc).
        headers = self._common_headers()
        headers["Idempotency-Key"] = self._idempotency_key(
            "POST", "/dsr/public/identity-proof", self._user_sub
        )
        # Authorization header is on the AsyncClient default headers.
        if not await self._cb.can_request():
            raise ServiceUnavailableError(
                status=None,
                code="circuit_open",
                message="circuit breaker is OPEN",
                request_id=self._request_id,
            )
        try:
            response = await self._http.request(
                "POST",
                "/dsr/public/identity-proof",
                data=data,
                files=files,
                headers=headers,
            )
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout) as exc:
            await self._cb.record_failure()
            raise ServiceUnavailableError(
                status=None,
                code="connection_error",
                message=str(exc),
                request_id=self._request_id,
            ) from exc
        if response.is_redirect:
            await self._cb.record_failure()
            raise UnexpectedRedirectError(
                status=response.status_code,
                code="unexpected_redirect",
                message="server returned redirect for upload; refusing",
                request_id=self._request_id,
            )
        if response.status_code >= 400:
            raise self._http_error(response)
        await self._cb.record_success()
        return IdentityProofScanResult.model_validate(response.json())

    async def get_dsr_receipt(
        self, *, reference: str, email: str
    ) -> dict[str, Any]:
        """AMD-05 ACL: RECEIPT_DOWNLOAD capability."""
        body = {"reference": reference, "email": email}
        r = await self._request(
            "POST", "/dsr/public/receipt", json_body=body, idempotent=True
        )
        return r.json()

    # ── Incidents (WI-10) ────────────────────────────────────────────────────
    async def list_incidents(self, **filters: Any) -> IncidentList:
        r = await self._request("GET", "/incidents", params=filters)
        return IncidentList.model_validate(r.json())

    async def get_incident(self, inc_id: str) -> Incident:
        r = await self._request("GET", f"/incidents/{inc_id}")
        return Incident.model_validate(r.json())

    async def create_incident(
        self,
        *,
        title: str,
        severity: str,
        triggered_at: str | None = None,
        source: str = "manual",
        affected_session_ids: list[str] | None = None,
        notes: str | None = None,
    ) -> Incident:
        body: dict[str, Any] = {
            "title": title,
            "severity": severity,
            "source": source,
        }
        if triggered_at is not None:
            body["triggered_at"] = triggered_at
        if affected_session_ids is not None:
            body["affected_session_ids"] = affected_session_ids
        if notes is not None:
            body["notes"] = notes
        r = await self._request(
            "POST", "/incidents", json_body=body, idempotent=True
        )
        return Incident.model_validate(r.json())

    async def add_incident_note(
        self,
        inc_id: str,
        *,
        content: str,
        rendered_html: str | None = None,
        tags: list[str] | None = None,
    ) -> IncidentNote:
        """REQ-CPL-017 — append-only note. AMD-19: caller passes pre-rendered
        HTML (markdown-it-py html=False + Bleach allowlist)."""
        body: dict[str, Any] = {"content": content}
        if rendered_html is not None:
            body["rendered_html"] = rendered_html
        if tags is not None:
            body["tags"] = tags
        r = await self._request(
            "POST", f"/incidents/{inc_id}/notes", json_body=body, idempotent=True
        )
        return IncidentNote.model_validate(r.json())

    async def add_incident_notification(
        self,
        inc_id: str,
        *,
        recipient: str,
        channel: str,
        confirmation_id: str | None = None,
        status: str = "sent",
    ) -> IncidentNotification:
        body: dict[str, Any] = {
            "recipient": recipient,
            "channel": channel,
            "status": status,
        }
        if confirmation_id is not None:
            body["confirmation_id"] = confirmation_id
        r = await self._request(
            "POST",
            f"/incidents/{inc_id}/notifications",
            json_body=body,
            idempotent=True,
        )
        return IncidentNotification.model_validate(r.json())

    async def transition_incident_status(
        self, inc_id: str, *, to_status: str, notes: str | None = None
    ) -> Incident:
        body: dict[str, Any] = {"to_status": to_status}
        if notes is not None:
            body["notes"] = notes
        r = await self._request(
            "POST", f"/incidents/{inc_id}/transition", json_body=body, idempotent=True
        )
        return Incident.model_validate(r.json())

    async def close_incident(
        self, inc_id: str, *, summary: str | None = None
    ) -> Incident:
        return await self.transition_incident_status(
            inc_id, to_status="closed", notes=summary
        )

    async def generate_incident_report(self, inc_id: str) -> dict[str, Any]:
        """REQ-CPL-018 — service composes report from notes/notifications/sessions."""
        r = await self._request(
            "POST", f"/incidents/{inc_id}/report", json_body={}, idempotent=True
        )
        return r.json()

    async def finalize_incident_report(
        self, inc_id: str
    ) -> EvidencePackage:
        """Promote the report to a signed evidence package."""
        r = await self._request(
            "POST",
            f"/incidents/{inc_id}/report/finalize",
            json_body={},
            idempotent=True,
        )
        return EvidencePackage.model_validate(r.json())

    # ── Model Cards (WI-11) ─────────────────────────────────────────────────
    async def list_model_cards(self, **filters: Any) -> list[ModelCard]:
        r = await self._request("GET", "/model-cards", params=filters)
        data = r.json()
        items = data.get("items") if isinstance(data, dict) else data
        return [ModelCard.model_validate(x) for x in items]

    async def get_model_card(self, model_id: str) -> ModelCard:
        r = await self._request("GET", f"/model-cards/{model_id}")
        return ModelCard.model_validate(r.json())

    async def schedule_model_review(
        self,
        model_id: str,
        *,
        scheduled_for: str,
        primary_reviewer_sub: str | None = None,
    ) -> ModelCardReview:
        body: dict[str, Any] = {"scheduled_for": scheduled_for}
        if primary_reviewer_sub is not None:
            body["primary_reviewer_sub"] = primary_reviewer_sub
        r = await self._request(
            "POST",
            f"/model-cards/{model_id}/reviews",
            json_body=body,
            idempotent=True,
        )
        return ModelCardReview.model_validate(r.json())

    async def transition_model_review(
        self,
        model_id: str,
        review_id: str,
        *,
        to_state: str,
        decision: str | None = None,
        rationale: str | None = None,
        evidence_package_id: str | None = None,
        external_url: str | None = None,
        external_label: str | None = None,
        reviewer_sub: str | None = None,
    ) -> ModelCardReview:
        body: dict[str, Any] = {"to_state": to_state}
        if decision is not None:
            body["decision"] = decision
        if rationale is not None:
            body["rationale"] = rationale
        if evidence_package_id is not None:
            body["evidence_package_id"] = evidence_package_id
        if external_url is not None:
            body["external_url"] = external_url
        if external_label is not None:
            body["external_label"] = external_label
        if reviewer_sub is not None:
            body["reviewer_sub"] = reviewer_sub
        r = await self._request(
            "POST",
            f"/model-cards/{model_id}/reviews/{review_id}/transition",
            json_body=body,
            idempotent=True,
        )
        return ModelCardReview.model_validate(r.json())

    async def sign_model_review(
        self,
        review_id: str,
        *,
        signed_by: str,
        decision_nonce: str,
    ) -> ModelCardReview:
        """AMD-03 — MFA per-decision binding via decision_nonce."""
        body = {"signed_by": signed_by, "decision_nonce": decision_nonce}
        r = await self._request(
            "POST",
            f"/model-cards/reviews/{review_id}/signoff",
            json_body=body,
            idempotent=True,
        )
        return ModelCardReview.model_validate(r.json())

    # ── Regulatory Reports (WI-12) ───────────────────────────────────────────
    async def list_reports(self, **filters: Any) -> RegulatoryReportList:
        r = await self._request("GET", "/reports", params=filters)
        return RegulatoryReportList.model_validate(r.json())

    async def get_report(self, report_id: str) -> RegulatoryReport:
        r = await self._request("GET", f"/reports/{report_id}")
        return RegulatoryReport.model_validate(r.json())

    async def generate_sox_report(
        self,
        *,
        period_start: str,
        period_end: str,
        scope_notes: str | None = None,
        control_owners: list[str] | None = None,
    ) -> RegulatoryReport:
        body: dict[str, Any] = {
            "report_type": "sox_attestation",
            "period_start": period_start,
            "period_end": period_end,
        }
        if scope_notes is not None:
            body["scope_notes"] = scope_notes
        if control_owners is not None:
            body["control_owners"] = control_owners
        r = await self._request("POST", "/reports", json_body=body, idempotent=True)
        return RegulatoryReport.model_validate(r.json())

    async def generate_ny_dfs_report(
        self,
        *,
        period_start: str,
        period_end: str,
        certifier_name: str,
        certifier_title: str,
        scope_notes: str | None = None,
    ) -> RegulatoryReport:
        body: dict[str, Any] = {
            "report_type": "nydfs_part500",
            "period_start": period_start,
            "period_end": period_end,
            "certifier_name": certifier_name,
            "certifier_title": certifier_title,
        }
        if scope_notes is not None:
            body["scope_notes"] = scope_notes
        r = await self._request("POST", "/reports", json_body=body, idempotent=True)
        return RegulatoryReport.model_validate(r.json())

    async def generate_eu_ai_act_report(
        self,
        *,
        high_risk_system_change_id: str,
        system_name: str,
        intended_purpose: str,
        model_card_id: str | None = None,
        scope_notes: str | None = None,
    ) -> RegulatoryReport:
        body: dict[str, Any] = {
            "report_type": "eu_ai_act_conformity",
            "high_risk_system_change_id": high_risk_system_change_id,
            "system_name": system_name,
            "intended_purpose": intended_purpose,
        }
        if model_card_id is not None:
            body["model_card_id"] = model_card_id
        if scope_notes is not None:
            body["scope_notes"] = scope_notes
        r = await self._request("POST", "/reports", json_body=body, idempotent=True)
        return RegulatoryReport.model_validate(r.json())

    async def generate_naic_adverse_action(
        self,
        *,
        triggering_event_id: str,
        affected_party: str,
        decision_summary: str,
        responsible_person: str,
        redress_option: str | None = None,
    ) -> RegulatoryReport:
        body: dict[str, Any] = {
            "report_type": "naic_adverse_action",
            "triggering_event_id": triggering_event_id,
            "affected_party": affected_party,
            "decision_summary": decision_summary,
            "responsible_person": responsible_person,
        }
        if redress_option is not None:
            body["redress_option"] = redress_option
        r = await self._request("POST", "/reports", json_body=body, idempotent=True)
        return RegulatoryReport.model_validate(r.json())

    async def transition_report(
        self,
        report_id: str,
        *,
        to_stage: str,
        rationale: str | None = None,
    ) -> RegulatoryReport:
        body: dict[str, Any] = {"to_stage": to_stage}
        if rationale is not None:
            body["rationale"] = rationale
        r = await self._request(
            "POST", f"/reports/{report_id}/transition", json_body=body, idempotent=True
        )
        return RegulatoryReport.model_validate(r.json())

    async def sign_report(
        self,
        report_id: str,
        *,
        signed_by: str,
        decision_nonce: str,
    ) -> RegulatoryReport:
        """AMD-03 + AMD-04 + AMD-08 — service signs with Ed25519 (PAdES byterange
        for PDF embedding handled by WI-19); signing_key_id resolves via JWKS.

        Portal NEVER computes the signature.
        """
        body = {"signed_by": signed_by, "decision_nonce": decision_nonce}
        r = await self._request(
            "POST", f"/reports/{report_id}/sign", json_body=body, idempotent=True
        )
        return RegulatoryReport.model_validate(r.json())

    async def deliver_report(
        self,
        report_id: str,
        *,
        recipient: str,
        channel: str,
        confirmation_receipt: str | None = None,
    ) -> ReportDelivery:
        body: dict[str, Any] = {
            "recipient": recipient,
            "channel": channel,
        }
        if confirmation_receipt is not None:
            body["confirmation_receipt"] = confirmation_receipt
        r = await self._request(
            "POST",
            f"/reports/{report_id}/delivery",
            json_body=body,
            idempotent=True,
        )
        return ReportDelivery.model_validate(r.json())

    # ── Compliance Dashboards (WI-13, REQ-CPL-027/028) ──────────────────────
    async def get_compliance_scores(self, framework: str) -> ComplianceScores:
        r = await self._request("GET", f"/compliance/{framework}/scores")
        return ComplianceScores.model_validate(r.json())

    async def get_compliance_trends(
        self, framework: str, period_days: int = 90
    ) -> ComplianceTrends:
        r = await self._request(
            "GET",
            f"/compliance/{framework}/trends",
            params={"period_days": period_days},
        )
        return ComplianceTrends.model_validate(r.json())

    async def get_gap_analysis(self, framework: str) -> ComplianceGapAnalysis:
        r = await self._request("GET", f"/compliance/{framework}/gaps")
        return ComplianceGapAnalysis.model_validate(r.json())

    async def get_control_detail(
        self, framework: str, control_id: str
    ) -> ComplianceControlDetail:
        r = await self._request(
            "GET", f"/compliance/{framework}/controls/{control_id}"
        )
        return ComplianceControlDetail.model_validate(r.json())

    # ── Process Knowledge (WI-14, REQ-CPL-029/030) ──────────────────────────
    async def list_knowledge_candidates(
        self, **filters: Any
    ) -> KnowledgeCandidateList:
        r = await self._request("GET", "/knowledge/candidates", params=filters)
        return KnowledgeCandidateList.model_validate(r.json())

    async def get_knowledge_candidate(
        self, candidate_id: str
    ) -> KnowledgeCandidate:
        r = await self._request("GET", f"/knowledge/candidates/{candidate_id}")
        return KnowledgeCandidate.model_validate(r.json())

    async def approve_candidate(
        self, candidate_id: str, *, rationale: str, decided_by: str
    ) -> KnowledgeCandidate:
        body = {
            "action": "approve",
            "rationale": rationale,
            "decided_by": decided_by,
        }
        r = await self._request(
            "POST",
            f"/knowledge/candidates/{candidate_id}/decision",
            json_body=body,
            idempotent=True,
        )
        return KnowledgeCandidate.model_validate(r.json())

    async def reject_candidate(
        self, candidate_id: str, *, rationale: str, decided_by: str
    ) -> KnowledgeCandidate:
        body = {
            "action": "reject",
            "rationale": rationale,
            "decided_by": decided_by,
        }
        r = await self._request(
            "POST",
            f"/knowledge/candidates/{candidate_id}/decision",
            json_body=body,
            idempotent=True,
        )
        return KnowledgeCandidate.model_validate(r.json())

    async def modify_candidate(
        self,
        candidate_id: str,
        *,
        modified_yaml: str,
        modified_by: str,
        rationale: str | None = None,
    ) -> KnowledgeCandidate:
        body: dict[str, Any] = {
            "modified_yaml": modified_yaml,
            "modified_by": modified_by,
        }
        if rationale is not None:
            body["rationale"] = rationale
        r = await self._request(
            "POST",
            f"/knowledge/candidates/{candidate_id}/modify",
            json_body=body,
            idempotent=True,
        )
        return KnowledgeCandidate.model_validate(r.json())

    async def batch_process_candidates(
        self,
        *,
        candidate_ids: list[str],
        action: str,  # approve | reject
        rationale: str,
        decided_by: str,
    ) -> KnowledgeBatchResult:
        """REQ-CPL-030 — batch operations."""
        body = {
            "candidate_ids": candidate_ids,
            "action": action,
            "rationale": rationale,
            "decided_by": decided_by,
        }
        r = await self._request(
            "POST",
            "/knowledge/candidates/batch",
            json_body=body,
            idempotent=True,
        )
        return KnowledgeBatchResult.model_validate(r.json())

    async def list_candidates_by_type(
        self, knowledge_type: str
    ) -> KnowledgeCandidateList:
        r = await self._request(
            "GET",
            "/knowledge/candidates",
            params={"knowledge_type": knowledge_type},
        )
        return KnowledgeCandidateList.model_validate(r.json())

    # ── Outcomes / Economics (WI-15, REQ-CPL-031/032) ───────────────────────
    async def get_cost_per_outcome(
        self, period_start: str, period_end: str
    ) -> OutcomeKPIs:
        r = await self._request(
            "GET",
            "/outcomes/cost-per-outcome",
            params={"period_start": period_start, "period_end": period_end},
        )
        return OutcomeKPIs.model_validate(r.json())

    async def get_quality_trends(
        self, period_start: str, period_end: str
    ) -> ComplianceTrends:
        r = await self._request(
            "GET",
            "/outcomes/quality-trends",
            params={"period_start": period_start, "period_end": period_end},
        )
        return ComplianceTrends.model_validate(r.json())

    async def get_agent_economics(
        self,
        period_start: str,
        period_end: str,
        *,
        agent: str | None = None,
        workflow: str | None = None,
        project: str | None = None,
    ) -> AgentEconomicsList:
        params: dict[str, Any] = {
            "period_start": period_start,
            "period_end": period_end,
        }
        if agent is not None:
            params["agent"] = agent
        if workflow is not None:
            params["workflow"] = workflow
        if project is not None:
            params["project"] = project
        r = await self._request("GET", "/outcomes/agent-economics", params=params)
        return AgentEconomicsList.model_validate(r.json())

    async def get_forecast_data(self, horizon_days: int = 30) -> ForecastData:
        r = await self._request(
            "GET", "/outcomes/forecast", params={"horizon_days": horizon_days}
        )
        return ForecastData.model_validate(r.json())

    async def get_outcome_summary(
        self, period_start: str, period_end: str
    ) -> OutcomeSummary:
        r = await self._request(
            "GET",
            "/outcomes/summary",
            params={"period_start": period_start, "period_end": period_end},
        )
        return OutcomeSummary.model_validate(r.json())

    # ── Project Documentation Portal (WI-16, REQ-CPL-040..044) ──────────────
    async def list_projects(self, **filters: Any) -> ProjectList:
        r = await self._request("GET", "/projects", params=filters)
        return ProjectList.model_validate(r.json())

    async def get_project(self, project_id: str) -> ProjectSummary:
        r = await self._request("GET", f"/projects/{project_id}")
        return ProjectSummary.model_validate(r.json())

    async def list_project_docs(
        self, project_id: str
    ) -> dict[str, Any]:
        """Returns hierarchical doc tree as nested dict; consumed by services/doc_tree."""
        r = await self._request("GET", f"/projects/{project_id}/docs")
        return r.json()

    async def get_project_doc(
        self, project_id: str, doc_path: str
    ) -> ProjectDoc:
        r = await self._request(
            "GET", f"/projects/{project_id}/docs/{doc_path}"
        )
        return ProjectDoc.model_validate(r.json())

    async def get_project_doc_history(
        self, project_id: str, doc_path: str
    ) -> DocVersionList:
        r = await self._request(
            "GET", f"/projects/{project_id}/docs/{doc_path}/history"
        )
        return DocVersionList.model_validate(r.json())

    async def search_project_docs(
        self,
        q: str,
        *,
        project_ids: list[str] | None = None,
        doc_types: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        author: str | None = None,
    ) -> SearchResults:
        params: dict[str, Any] = {"q": q}
        if project_ids:
            params["project_ids"] = ",".join(project_ids)
        if doc_types:
            params["doc_types"] = ",".join(doc_types)
        if date_from:
            params["date_from"] = date_from
        if date_to:
            params["date_to"] = date_to
        if author:
            params["author"] = author
        r = await self._request("GET", "/projects/search", params=params)
        return SearchResults.model_validate(r.json())

    async def global_search(self, q: str) -> dict[str, Any]:
        """Cross-area search. Returns the raw {query, items, total} structure;
        each item is {category, title, subtitle, href}. Kept as a dict (rather
        than a typed model) because hits span heterogeneous entity types."""
        r = await self._request("GET", "/search", params={"q": q})
        return r.json()

    async def get_sla_trends(self, domain: str = "gates", sla_hours: int = 24) -> dict[str, Any]:
        """SLA performance over time (decision turnaround), bucketed by week."""
        r = await self._request(
            "GET", "/metrics/sla-trends",
            params={"domain": domain, "sla_hours": sla_hours},
        )
        return r.json()

    async def get_evidence_coverage(self) -> dict[str, Any]:
        """Per-project BRD requirement coverage rollup."""
        r = await self._request("GET", "/evidence/coverage")
        return r.json()

    async def get_doc_diff(
        self,
        project_id: str,
        doc_path: str,
        from_sha: str,
        to_sha: str,
    ) -> DocDiff:
        r = await self._request(
            "GET",
            f"/projects/{project_id}/docs/{doc_path}/diff",
            params={"from": from_sha, "to": to_sha},
        )
        return DocDiff.model_validate(r.json())

    async def generate_zip_export(
        self, project_id: str
    ) -> dict[str, Any]:
        """Initiates a ZIP export. Service returns bytes/streaming details."""
        r = await self._request(
            "POST",
            f"/projects/{project_id}/export/zip",
            json_body={},
            idempotent=True,
        )
        return r.json()

    # Health (used by /readyz)
    async def health(self) -> bool:
        try:
            r = await self._request("GET", "/healthz", max_attempts=1)
            return r.status_code == 200
        except ComplianceClientError:
            return False


__all__ = ["ComplianceClient"]
