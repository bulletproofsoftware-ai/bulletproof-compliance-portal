"""Shared fake ComplianceClient for router-level tests.

Implements the subset of the ComplianceClient surface used by WI-04, WI-05,
WI-06, WI-07. Tests inject this via `app.dependency_overrides`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from shared.api_client import (
    AgentEconomicsList,
    AuditEvent,
    AuditEventList,
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
    EngagementAccessLogEntry,
    EvidenceDiff,
    EvidenceDownload,
    EvidencePackage,
    EvidencePackageList,
    EvidenceSignatureStatus,
    EvidenceVersion,
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
    ModelCardResponsible,
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
from shared.api_client.models import AuditRecordResult


_NOW = datetime.now(UTC)


class FakeComplianceClient:
    """Programmable in-memory fake. Tests construct, seed, and assert against
    captured calls. Mirrors the real ComplianceClient signature for the
    handful of methods exercised by WI-04..07."""

    def __init__(self) -> None:
        self.audit_events: list[AuditEvent] = []
        self.evidence_packages: list[EvidencePackage] = []
        self.evidence_versions: dict[str, list[EvidenceVersion]] = {}
        self.evidence_diffs: dict[tuple[str, str, str], EvidenceDiff] = {}
        self.evidence_signatures: dict[str, EvidenceSignatureStatus] = {}
        self.evidence_downloads: dict[str, EvidenceDownload] = {}
        self.gates: dict[str, HumanGate] = {}
        self.gate_receipts: dict[str, GateDecisionReceipt] = {}
        self.engagements: dict[str, AuditorEngagement] = {}
        self.engagement_logs: dict[str, list[EngagementAccessLogEntry]] = {}
        self.recorded_audit_events: list[dict[str, Any]] = []
        # Optional override for verify_hash_chain
        self.hash_chain_verdict_ok: bool = True
        # Capture decide_human_gate calls
        self.decide_calls: list[dict[str, Any]] = []
        self.create_engagement_calls: list[dict[str, Any]] = []
        self.revoke_engagement_calls: list[dict[str, Any]] = []

    # ── Audit ────────────────────────────────────────────────────────────────

    async def list_audit_events(self, **filters: Any) -> AuditEventList:
        items = list(self.audit_events)
        if "session_id" in filters:
            items = [
                ev for ev in items
                if ev.payload.get("session_id") == filters["session_id"]
            ]
        if "user_id" in filters:
            items = [ev for ev in items if ev.user_id == filters["user_id"]]
        if "classification" in filters:
            items = [ev for ev in items if ev.classification == filters["classification"]]
        if "event_type" in filters:
            items = [ev for ev in items if ev.audit_type == filters["event_type"]]
        return AuditEventList(items=items, next_cursor=None, total=len(items))

    async def get_audit_event(self, event_id: str) -> AuditEvent:
        for ev in self.audit_events:
            if ev.event_id == event_id:
                return ev
        raise KeyError(event_id)

    async def verify_hash_chain(
        self, from_id: int, to_id: int
    ) -> HashChainVerification:
        return HashChainVerification(
            ok=self.hash_chain_verdict_ok,
            from_index=from_id,
            to_index=to_id,
            mismatched_at=None if self.hash_chain_verdict_ok else from_id,
        )

    async def global_search(self, q: str) -> dict[str, Any]:
        needle = (q or "").strip().lower()
        items: list[dict[str, Any]] = []
        if needle:
            for ev in self.audit_events:
                if needle in f"{ev.audit_type} {ev.event_id} {ev.user_id or ''}".lower():
                    items.append({"category": "Audit", "title": ev.audit_type,
                                  "subtitle": ev.event_id, "href": "/audit"})
            for g in getattr(self, "gates", {}).values():
                if needle in f"{g.title} {g.gate_id}".lower():
                    items.append({"category": "Gate", "title": g.title,
                                  "subtitle": g.gate_id, "href": f"/gates/{g.gate_id}"})
        return {"query": q, "items": items[:50], "total": len(items)}

    async def get_sla_trends(self, domain: str = "gates", sla_hours: int = 24) -> dict[str, Any]:
        return getattr(self, "sla_trends_payload", {
            "domain": domain, "sla_hours": sla_hours,
            "points": [
                {"period": "2026-W19", "count": 3, "on_time": 2, "on_time_rate": 66.7, "avg_turnaround_hours": 18.5},
                {"period": "2026-W20", "count": 5, "on_time": 5, "on_time_rate": 100.0, "avg_turnaround_hours": 6.2},
            ],
            "total": 8,
        })

    async def get_evidence_coverage(self) -> dict[str, Any]:
        return getattr(self, "evidence_coverage_payload", {
            "projects": [
                {"project_id": "proj-a", "total": 10, "covered": 7, "coverage_pct": 70.0},
                {"project_id": "proj-b", "total": 4, "covered": 4, "coverage_pct": 100.0},
            ],
            "overall_total": 14, "overall_covered": 11, "overall_pct": 78.6,
        })

    async def record_audit_event(
        self,
        *,
        audit_type: str,
        user_id: str | None = None,
        classification: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecordResult:
        self.recorded_audit_events.append(
            {
                "audit_type": audit_type,
                "user_id": user_id,
                "classification": classification,
                "payload": payload or {},
            }
        )
        return AuditRecordResult(
            event_id=f"rec-{len(self.recorded_audit_events)}",
            ts=datetime.now(UTC),
            accepted=True,
        )

    # ── Evidence ────────────────────────────────────────────────────────────

    async def list_evidence_packages(self, **_: Any) -> EvidencePackageList:
        return EvidencePackageList(
            items=list(self.evidence_packages),
            next_cursor=None,
            total=len(self.evidence_packages),
        )

    async def get_evidence_package(self, pkg_id: str) -> EvidencePackage:
        for p in self.evidence_packages:
            if p.package_id == pkg_id:
                return p
        raise KeyError(pkg_id)

    async def list_evidence_versions(self, pkg_id: str) -> EvidenceVersionList:
        return EvidenceVersionList(
            package_id=pkg_id, items=self.evidence_versions.get(pkg_id, [])
        )

    async def get_evidence_diff(
        self, pkg_id: str, *, from_version: str, to_version: str
    ) -> EvidenceDiff:
        key = (pkg_id, from_version, to_version)
        if key in self.evidence_diffs:
            return self.evidence_diffs[key]
        return EvidenceDiff(
            package_id=pkg_id,
            from_version=from_version,
            to_version=to_version,
            diff_text="(no diff seeded)",
        )

    async def verify_evidence_signature(
        self, pkg_id: str, *, version: str | None = None
    ) -> EvidenceSignatureStatus:
        if pkg_id in self.evidence_signatures:
            return self.evidence_signatures[pkg_id]
        return EvidenceSignatureStatus(
            package_id=pkg_id,
            version=version or "v1",
            valid=True,
            algorithm="Ed25519",
            signing_key_id="key-2026-q1",
            signed_at=_NOW,
        )

    async def get_evidence_download_metadata(
        self, pkg_id: str, *, version: str | None = None, purpose: str | None = None
    ) -> EvidenceDownload:
        if pkg_id in self.evidence_downloads:
            return self.evidence_downloads[pkg_id]
        return EvidenceDownload(
            package_id=pkg_id,
            version=version or "v1",
            filename=f"{pkg_id}.zip",
            media_type="application/zip",
            size_bytes=1024,
            download_url=f"https://compliance.test/dl/{pkg_id}",
            artifact_hash="abc123",
        )

    # ── Gates ───────────────────────────────────────────────────────────────

    async def list_human_gates(self, **_: Any) -> HumanGateList:
        items = list(self.gates.values())
        return HumanGateList(items=items, total=len(items))

    async def get_human_gate(self, gate_id: str) -> HumanGate:
        if gate_id in self.gates:
            return self.gates[gate_id]
        raise KeyError(gate_id)

    async def decide_human_gate(
        self,
        gate_id: str,
        *,
        decision: str,
        rationale: str,
        decision_nonce: str | None = None,
        escalate_to_role: str | None = None,
    ) -> GateDecisionReceipt:
        self.decide_calls.append(
            {
                "gate_id": gate_id,
                "decision": decision,
                "rationale": rationale,
                "decision_nonce": decision_nonce,
                "escalate_to_role": escalate_to_role,
            }
        )
        receipt = GateDecisionReceipt(
            receipt_id=f"rcpt-{gate_id}-{len(self.decide_calls)}",
            gate_id=gate_id,
            decision=decision,
            rationale=rationale,
            decided_by="test-user",
            decided_at=datetime.now(UTC),
            signature="ZmFrZS1zaWduYXR1cmU=" * 4,
            signing_key_id="key-2026-q1",
            evidence_snapshot=[],
            escalate_to_role=escalate_to_role,
        )
        self.gate_receipts[gate_id] = receipt
        return receipt

    async def get_gate_receipt(self, gate_id: str) -> GateDecisionReceipt:
        if gate_id in self.gate_receipts:
            return self.gate_receipts[gate_id]
        raise KeyError(gate_id)

    # ── Engagements ─────────────────────────────────────────────────────────

    async def list_engagements(self, **_: Any) -> AuditorEngagementList:
        items = list(self.engagements.values())
        return AuditorEngagementList(items=items, total=len(items))

    async def get_engagement(self, engagement_id: str) -> AuditorEngagement:
        if engagement_id in self.engagements:
            return self.engagements[engagement_id]
        raise KeyError(engagement_id)

    async def create_engagement(
        self,
        *,
        auditor_email: str,
        engagement_start: str,
        engagement_end: str,
        date_range_start: str,
        date_range_end: str,
        allowed_artifact_types: list[str],
        allowed_project_ids: list[str] | None = None,
    ) -> AuditorEngagement:
        engagement_id = f"ENG-{len(self.engagements) + 1:04d}"
        eng = AuditorEngagement(
            engagement_id=engagement_id,
            auditor_email=auditor_email,
            engagement_start=datetime.fromisoformat(engagement_start),
            engagement_end=datetime.fromisoformat(engagement_end),
            date_range_start=datetime.fromisoformat(date_range_start),
            date_range_end=datetime.fromisoformat(date_range_end),
            allowed_artifact_types=allowed_artifact_types,
            allowed_project_ids=allowed_project_ids,
            state="active",
            created_at=datetime.now(UTC),
        )
        self.engagements[engagement_id] = eng
        self.create_engagement_calls.append({"auditor_email": auditor_email})
        return eng

    async def revoke_engagement(
        self, engagement_id: str, *, reason: str
    ) -> AuditorEngagement:
        if engagement_id not in self.engagements:
            raise KeyError(engagement_id)
        existing = self.engagements[engagement_id]
        revoked = existing.model_copy(
            update={
                "state": "revoked",
                "revoked_at": datetime.now(UTC),
                "revoked_reason": reason,
            }
        )
        self.engagements[engagement_id] = revoked
        self.revoke_engagement_calls.append({"engagement_id": engagement_id, "reason": reason})
        return revoked

    async def get_engagement_access_log(
        self, engagement_id: str, **_: Any
    ) -> EngagementAccessLog:
        return EngagementAccessLog(
            engagement_id=engagement_id,
            items=self.engagement_logs.get(engagement_id, []),
        )

    async def log_engagement_access(
        self,
        engagement_id: str,
        *,
        artifact_type: str,
        artifact_id: str,
        action: str = "view",
    ) -> AuditRecordResult:
        entry = EngagementAccessLogEntry(
            engagement_id=engagement_id,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            accessed_at=datetime.now(UTC),
            action=action,
        )
        self.engagement_logs.setdefault(engagement_id, []).append(entry)
        return await self.record_audit_event(
            audit_type=f"auditor.artifact.{action}",
            classification="confidential",
            payload={
                "engagement_id": engagement_id,
                "artifact_type": artifact_type,
                "artifact_id": artifact_id,
            },
        )

    # ── DSR ─────────────────────────────────────────────────────────────────

    def _ensure_dsr_storage(self) -> None:
        if not hasattr(self, "dsr_requests"):
            self.dsr_requests: dict[str, DsrRequest] = {}
            self.dsr_transitions: list[dict[str, Any]] = []
            self.dsr_evidence_jobs: dict[str, DsrEvidenceJob] = {}
            self.dsr_delivery_tokens: dict[str, list[DsrDeliveryToken]] = {}
            self.dsr_public_submissions: list[dict[str, Any]] = []
            self.dsr_identity_uploads: list[dict[str, Any]] = []
            self.dsr_public_statuses: dict[tuple[str, str], DsrPublicStatus] = {}
            self.dsr_evidence_next_job_id: int = 1
            # Optional: forced scan verdicts for testing
            self.dsr_force_scan_status: str | None = None

    async def list_dsr_requests(self, **filters: Any) -> DsrRequestList:
        self._ensure_dsr_storage()
        items = list(self.dsr_requests.values())
        if "request_type" in filters:
            items = [r for r in items if r.request_type == filters["request_type"]]
        if "status" in filters:
            items = [r for r in items if r.status == filters["status"]]
        return DsrRequestList(items=items, total=len(items))

    async def get_dsr_request(self, req_id: str) -> DsrRequest:
        self._ensure_dsr_storage()
        if req_id in self.dsr_requests:
            return self.dsr_requests[req_id]
        raise KeyError(req_id)

    async def submit_dsr_request(self, **kwargs: Any) -> DsrRequest:
        self._ensure_dsr_storage()
        req_id = f"DSR-{len(self.dsr_requests) + 1:04d}"
        req = DsrRequest(
            request_id=req_id,
            request_type=kwargs["request_type"],
            status="received",
            submitted_at=datetime.now(UTC),
            submitted_by=kwargs.get("submitted_by"),
            subject_email=kwargs.get("subject_email"),
            subject_name=kwargs.get("subject_name"),
            source=kwargs.get("source", "internal"),
            identity_proof_id=kwargs.get("identity_proof_id"),
        )
        self.dsr_requests[req_id] = req
        return req

    async def transition_dsr_status(
        self, req_id: str, *, to_status: str, **kwargs: Any
    ) -> DsrTransitionResult:
        self._ensure_dsr_storage()
        req = self.dsr_requests.get(req_id)
        if req is None:
            raise KeyError(req_id)
        from_status = req.status
        # AMD-12 — invalidate outstanding tokens on close.
        invalidated = 0
        if to_status in {"closed", "rejected", "identity_rejected"}:
            tokens = self.dsr_delivery_tokens.get(req_id, [])
            invalidated = len([t for t in tokens])
            self.dsr_delivery_tokens[req_id] = []
        # Update transition list on the model.
        new_transitions = list(req.transitions) + [
            {
                "from": from_status,
                "to": to_status,
                "at": datetime.now(UTC).isoformat(),
                "by": kwargs.get("transitioned_by", "test-user"),
                "notes": kwargs.get("notes"),
            }
        ]
        new_req = req.model_copy(
            update={"status": to_status, "transitions": new_transitions}
        )
        self.dsr_requests[req_id] = new_req
        result = DsrTransitionResult(
            request_id=req_id,
            from_status=from_status,
            to_status=to_status,
            transitioned_at=datetime.now(UTC),
            transitioned_by=kwargs.get("transitioned_by", "test-user"),
            invalidated_token_count=invalidated,
            notes=kwargs.get("notes"),
        )
        self.dsr_transitions.append(result.model_dump(mode="json"))
        return result

    async def generate_dsr_evidence(self, req_id: str) -> DsrEvidenceJob:
        self._ensure_dsr_storage()
        if req_id not in self.dsr_requests:
            raise KeyError(req_id)
        # Default behaviour: synchronous package creation — return 200 form.
        job = DsrEvidenceJob(
            request_id=req_id,
            job_id=None,
            status="complete",
            evidence_package_id=f"EVD-DSR-{req_id}",
        )
        # Allow tests to override to async (job_id form) by setting on instance.
        if getattr(self, "_dsr_evidence_async", False):
            job = DsrEvidenceJob(
                request_id=req_id,
                job_id=f"job-{self.dsr_evidence_next_job_id}",
                status="pending",
            )
            self.dsr_evidence_next_job_id += 1
        # Auto-transition to evidence_generated when synchronous complete.
        if job.evidence_package_id:
            req = self.dsr_requests[req_id]
            self.dsr_requests[req_id] = req.model_copy(
                update={
                    "status": "evidence_generated",
                    "evidence_package_id": job.evidence_package_id,
                }
            )
        self.dsr_evidence_jobs[req_id] = job
        return job

    async def deliver_dsr(
        self, req_id: str, *, package_id: str, version: str = "v1"
    ) -> DsrDeliveryToken:
        self._ensure_dsr_storage()
        if req_id not in self.dsr_requests:
            raise KeyError(req_id)
        from datetime import timedelta

        token = DsrDeliveryToken(
            request_id=req_id,
            token=f"tok-{req_id}-{len(self.dsr_delivery_tokens.get(req_id, []))}",
            expires_at=datetime.now(UTC) + timedelta(days=7),
            package_id=package_id,
            version=version,
        )
        self.dsr_delivery_tokens.setdefault(req_id, []).append(token)
        # Auto-transition to delivered.
        req = self.dsr_requests[req_id]
        self.dsr_requests[req_id] = req.model_copy(update={"status": "delivered"})
        return token

    async def close_dsr(self, req_id: str, **kwargs: Any) -> DsrTransitionResult:
        return await self.transition_dsr_status(req_id, to_status="closed", **kwargs)

    async def submit_public_dsr(self, **kwargs: Any) -> DsrPublicSubmissionResult:
        self._ensure_dsr_storage()
        # Reuse the internal submit flow + add a reference number.
        req = await self.submit_dsr_request(source="public", **kwargs)
        ref = f"DSR-PUB-{req.request_id}"
        result = DsrPublicSubmissionResult(
            reference=ref,
            request_id=req.request_id,
            submitted_at=req.submitted_at,
            identity_proof_status="pending",
        )
        self.dsr_public_submissions.append({"reference": ref, "request_id": req.request_id})
        return result

    async def check_dsr_status_by_token(
        self, *, reference: str, email: str
    ) -> DsrPublicStatus:
        self._ensure_dsr_storage()
        key = (reference, email.lower().strip())
        if key in self.dsr_public_statuses:
            return self.dsr_public_statuses[key]
        raise KeyError(key)

    async def upload_identity_proof(
        self, **kwargs: Any
    ) -> IdentityProofScanResult:
        self._ensure_dsr_storage()
        forced = self.dsr_force_scan_status
        proof_id = f"proof-{len(self.dsr_identity_uploads) + 1}"
        scan_status = forced or "clean"
        result = IdentityProofScanResult(
            proof_id=proof_id,
            scan_status=scan_status,
            scan_engine="ClamAV-fake",
            reason=None if scan_status == "clean" else "test_forced_verdict",
        )
        self.dsr_identity_uploads.append(
            {
                "reference": kwargs.get("reference"),
                "email": kwargs.get("email"),
                "filename": kwargs.get("filename"),
                "scan_status": scan_status,
            }
        )
        return result

    async def get_dsr_receipt(self, **kwargs: Any) -> dict[str, Any]:
        return {"reference": kwargs["reference"], "format": "pdf"}

    # ── Incidents ───────────────────────────────────────────────────────────

    def _ensure_incidents_storage(self) -> None:
        if not hasattr(self, "incidents_storage"):
            self.incidents_storage: dict[str, Incident] = {}
            self.incident_create_calls: list[dict[str, Any]] = []

    async def list_incidents(self, **filters: Any) -> IncidentList:
        self._ensure_incidents_storage()
        items = list(self.incidents_storage.values())
        if "severity" in filters:
            items = [i for i in items if i.severity == filters["severity"]]
        if "status" in filters:
            items = [i for i in items if i.status == filters["status"]]
        return IncidentList(items=items, total=len(items))

    async def get_incident(self, inc_id: str) -> Incident:
        self._ensure_incidents_storage()
        if inc_id in self.incidents_storage:
            return self.incidents_storage[inc_id]
        raise KeyError(inc_id)

    async def create_incident(self, **kwargs: Any) -> Incident:
        self._ensure_incidents_storage()
        inc_id = f"INC-{len(self.incidents_storage) + 1:04d}"
        from datetime import datetime as _dt

        triggered_at = kwargs.get("triggered_at")
        if isinstance(triggered_at, str):
            try:
                triggered_at = _dt.fromisoformat(triggered_at.replace("Z", "+00:00"))
            except ValueError:
                triggered_at = datetime.now(UTC)
        elif triggered_at is None:
            triggered_at = datetime.now(UTC)
        incident = Incident(
            incident_id=inc_id,
            title=kwargs.get("title"),
            severity=kwargs.get("severity", "high"),
            status="open",
            detected_at=datetime.now(UTC),
            triggered_at=triggered_at,
            affected_session_ids=kwargs.get("affected_session_ids") or [],
            source=kwargs.get("source", "manual"),
        )
        self.incidents_storage[inc_id] = incident
        self.incident_create_calls.append(dict(kwargs))
        return incident

    async def add_incident_note(
        self, inc_id: str, *, content: str, rendered_html: str | None = None,
        tags: list[str] | None = None,
    ) -> IncidentNote:
        self._ensure_incidents_storage()
        if inc_id not in self.incidents_storage:
            raise KeyError(inc_id)
        note = IncidentNote(
            note_id=f"note-{inc_id}-{len(self.incidents_storage[inc_id].notes) + 1}",
            author_sub="test-user",
            author_name="Test User",
            created_at=datetime.now(UTC),
            content=content,
            rendered_html=rendered_html,
            tags=tags or [],
        )
        existing = self.incidents_storage[inc_id]
        self.incidents_storage[inc_id] = existing.model_copy(
            update={"notes": list(existing.notes) + [note]}
        )
        return note

    async def add_incident_notification(
        self, inc_id: str, *, recipient: str, channel: str,
        confirmation_id: str | None = None, status: str = "sent",
    ) -> IncidentNotification:
        self._ensure_incidents_storage()
        if inc_id not in self.incidents_storage:
            raise KeyError(inc_id)
        n = IncidentNotification(
            notification_id=f"ntf-{inc_id}-{len(self.incidents_storage[inc_id].notifications) + 1}",
            recipient=recipient,
            channel=channel,
            sent_at=datetime.now(UTC),
            confirmation_id=confirmation_id,
            status=status,
        )
        existing = self.incidents_storage[inc_id]
        self.incidents_storage[inc_id] = existing.model_copy(
            update={"notifications": list(existing.notifications) + [n]}
        )
        return n

    async def transition_incident_status(
        self, inc_id: str, *, to_status: str, notes: str | None = None
    ) -> Incident:
        self._ensure_incidents_storage()
        if inc_id not in self.incidents_storage:
            raise KeyError(inc_id)
        existing = self.incidents_storage[inc_id]
        self.incidents_storage[inc_id] = existing.model_copy(update={"status": to_status})
        return self.incidents_storage[inc_id]

    async def close_incident(self, inc_id: str, *, summary: str | None = None) -> Incident:
        return await self.transition_incident_status(inc_id, to_status="closed", notes=summary)

    async def generate_incident_report(self, inc_id: str) -> dict[str, Any]:
        self._ensure_incidents_storage()
        return {"incident_id": inc_id, "draft": True, "report_text": "stub"}

    async def finalize_incident_report(self, inc_id: str) -> EvidencePackage:
        return EvidencePackage(
            package_id=f"EVD-INC-{inc_id}",
            title=f"Incident report {inc_id}",
            version="v1",
            classification="confidential",
            signed_by="compliance-svc",
            created_at=datetime.now(UTC),
        )

    # ── Model Cards ─────────────────────────────────────────────────────────

    def _ensure_model_storage(self) -> None:
        if not hasattr(self, "model_cards_storage"):
            self.model_cards_storage: dict[str, ModelCard] = {}

    async def list_model_cards(self, **filters: Any) -> list[ModelCard]:
        self._ensure_model_storage()
        cards = list(self.model_cards_storage.values())
        if "family" in filters:
            cards = [c for c in cards if c.family == filters["family"]]
        if "risk_tier" in filters:
            cards = [c for c in cards if c.risk_tier == filters["risk_tier"]]
        return cards

    async def get_model_card(self, model_id: str) -> ModelCard:
        self._ensure_model_storage()
        if model_id in self.model_cards_storage:
            return self.model_cards_storage[model_id]
        raise KeyError(model_id)

    async def schedule_model_review(
        self, model_id: str, *, scheduled_for: str, primary_reviewer_sub: str | None = None,
    ) -> ModelCardReview:
        self._ensure_model_storage()
        existing = self.model_cards_storage[model_id]
        from datetime import datetime as _dt

        try:
            sf = _dt.fromisoformat(scheduled_for.replace("Z", "+00:00"))
        except ValueError:
            sf = datetime.now(UTC)
        review = ModelCardReview(
            review_id=f"REV-{model_id}-{len(existing.reviews) + 1}",
            model_id=model_id,
            state="scheduled",
            scheduled_for=sf,
            reviewer_sub=primary_reviewer_sub,
        )
        self.model_cards_storage[model_id] = existing.model_copy(
            update={"reviews": list(existing.reviews) + [review], "next_review_date": sf}
        )
        return review

    async def transition_model_review(
        self, model_id: str, review_id: str, *, to_state: str, **kwargs: Any
    ) -> ModelCardReview:
        self._ensure_model_storage()
        card = self.model_cards_storage[model_id]
        new_reviews = []
        updated = None
        for r in card.reviews:
            if r.review_id == review_id:
                updated = r.model_copy(
                    update={
                        "state": to_state,
                        "decision": kwargs.get("decision") or r.decision,
                        "rationale": kwargs.get("rationale") or r.rationale,
                        "reviewer_sub": kwargs.get("reviewer_sub") or r.reviewer_sub,
                    }
                )
                new_reviews.append(updated)
            else:
                new_reviews.append(r)
        if updated is None:
            raise KeyError(review_id)
        self.model_cards_storage[model_id] = card.model_copy(update={"reviews": new_reviews})
        return updated

    async def sign_model_review(
        self, review_id: str, *, signed_by: str, decision_nonce: str
    ) -> ModelCardReview:
        self._ensure_model_storage()
        for model_id, card in self.model_cards_storage.items():
            for i, r in enumerate(card.reviews):
                if r.review_id == review_id:
                    signed = r.model_copy(
                        update={
                            "state": "signed_off",
                            "signed_at": datetime.now(UTC),
                            "signed_by": signed_by,
                            "signature": "ZmFrZS1zaWduYXR1cmU=" * 4,
                            "signing_key_id": "key-2026-q1",
                        }
                    )
                    new_reviews = list(card.reviews)
                    new_reviews[i] = signed
                    self.model_cards_storage[model_id] = card.model_copy(
                        update={"reviews": new_reviews}
                    )
                    return signed
        raise KeyError(review_id)

    # ── Reports ─────────────────────────────────────────────────────────────

    def _ensure_reports_storage(self) -> None:
        if not hasattr(self, "reports_storage"):
            self.reports_storage: dict[str, RegulatoryReport] = {}

    async def list_reports(self, **filters: Any) -> RegulatoryReportList:
        self._ensure_reports_storage()
        items = list(self.reports_storage.values())
        if "report_type" in filters:
            items = [r for r in items if r.report_type == filters["report_type"]]
        if "stage" in filters:
            items = [r for r in items if r.stage == filters["stage"]]
        return RegulatoryReportList(items=items, total=len(items))

    async def get_report(self, report_id: str) -> RegulatoryReport:
        self._ensure_reports_storage()
        if report_id in self.reports_storage:
            return self.reports_storage[report_id]
        raise KeyError(report_id)

    def _make_report(self, **kwargs: Any) -> RegulatoryReport:
        from datetime import datetime as _dt

        rid = f"RPT-{len(self.reports_storage) + 1:04d}"
        ps = kwargs.get("period_start")
        pe = kwargs.get("period_end")
        if isinstance(ps, str):
            try:
                ps = _dt.fromisoformat(ps.replace("Z", "+00:00"))
            except ValueError:
                ps = None
        if isinstance(pe, str):
            try:
                pe = _dt.fromisoformat(pe.replace("Z", "+00:00"))
            except ValueError:
                pe = None
        report = RegulatoryReport(
            report_id=rid,
            report_type=kwargs.get("report_type", "sox_attestation"),
            stage="draft",
            period_start=ps,
            period_end=pe,
            triggering_event_id=kwargs.get("triggering_event_id"),
            high_risk_system_change_id=kwargs.get("high_risk_system_change_id"),
            scope_notes=kwargs.get("scope_notes"),
            created_at=datetime.now(UTC),
            created_by=kwargs.get("created_by", "test-user"),
        )
        self.reports_storage[rid] = report
        return report

    async def generate_sox_report(self, **kwargs: Any) -> RegulatoryReport:
        self._ensure_reports_storage()
        return self._make_report(report_type="sox_attestation", **kwargs)

    async def generate_ny_dfs_report(self, **kwargs: Any) -> RegulatoryReport:
        self._ensure_reports_storage()
        return self._make_report(report_type="nydfs_part500", **kwargs)

    async def generate_eu_ai_act_report(self, **kwargs: Any) -> RegulatoryReport:
        self._ensure_reports_storage()
        return self._make_report(report_type="eu_ai_act_conformity", **kwargs)

    async def generate_naic_adverse_action(self, **kwargs: Any) -> RegulatoryReport:
        self._ensure_reports_storage()
        return self._make_report(report_type="naic_adverse_action", **kwargs)

    async def transition_report(
        self, report_id: str, *, to_stage: str, rationale: str | None = None
    ) -> RegulatoryReport:
        self._ensure_reports_storage()
        if report_id not in self.reports_storage:
            raise KeyError(report_id)
        existing = self.reports_storage[report_id]
        update: dict[str, Any] = {"stage": to_stage}
        if to_stage == "approved":
            update["approved_by"] = "test-admin"
            update["approved_at"] = datetime.now(UTC)
        new = existing.model_copy(update=update)
        self.reports_storage[report_id] = new
        return new

    async def sign_report(
        self, report_id: str, *, signed_by: str, decision_nonce: str
    ) -> RegulatoryReport:
        self._ensure_reports_storage()
        if report_id not in self.reports_storage:
            raise KeyError(report_id)
        existing = self.reports_storage[report_id]
        signed = existing.model_copy(
            update={
                "stage": "signed",
                "signed_at": datetime.now(UTC),
                "signed_by": signed_by,
                "signature": "ZmFrZS1zaWduYXR1cmU=" * 4,
                "signing_key_id": "key-2026-q1",
            }
        )
        self.reports_storage[report_id] = signed
        return signed

    async def deliver_report(
        self, report_id: str, *, recipient: str, channel: str,
        confirmation_receipt: str | None = None,
    ) -> ReportDelivery:
        self._ensure_reports_storage()
        existing = self.reports_storage[report_id]
        d = ReportDelivery(
            delivery_id=f"DEL-{report_id}-{len(existing.deliveries) + 1}",
            report_id=report_id,
            channel=channel,
            recipient=recipient,
            delivered_at=datetime.now(UTC),
            confirmation_receipt=confirmation_receipt,
        )
        self.reports_storage[report_id] = existing.model_copy(
            update={"deliveries": list(existing.deliveries) + [d]}
        )
        return d


    # ── Compliance Dashboards (WI-13) ───────────────────────────────────────

    def _ensure_dashboards_storage(self) -> None:
        if not hasattr(self, "compliance_scores_storage"):
            self.compliance_scores_storage: dict[str, ComplianceScores] = {}
            self.compliance_trends_storage: dict[str, ComplianceTrends] = {}
            self.compliance_gaps_storage: dict[str, ComplianceGapAnalysis] = {}
            self.compliance_controls_storage: dict[
                tuple[str, str], ComplianceControlDetail
            ] = {}

    async def get_compliance_scores(self, framework: str) -> ComplianceScores:
        self._ensure_dashboards_storage()
        if framework in self.compliance_scores_storage:
            return self.compliance_scores_storage[framework]
        # Default seed: empty score model.
        from shared.api_client.models import ComplianceDomainScore

        return ComplianceScores(
            framework=framework,
            overall_score=80.0,
            asof=datetime.now(UTC),
            domain_scores=[
                ComplianceDomainScore(domain="governance", score=82.0),
                ComplianceDomainScore(domain="data", score=78.0),
            ],
            regression_flag=False,
        )

    async def get_compliance_trends(
        self, framework: str, period_days: int = 90
    ) -> ComplianceTrends:
        self._ensure_dashboards_storage()
        if framework in self.compliance_trends_storage:
            return self.compliance_trends_storage[framework]
        from shared.api_client.models import ComplianceTrendPoint

        now = datetime.now(UTC)
        return ComplianceTrends(
            framework=framework,
            period_days=period_days,
            points=[
                ComplianceTrendPoint(
                    asof=now - timedelta(days=period_days - i),
                    score=78.0 + (i % 5),
                )
                for i in range(min(period_days, 10))
            ],
        )

    async def get_gap_analysis(self, framework: str) -> ComplianceGapAnalysis:
        self._ensure_dashboards_storage()
        if framework in self.compliance_gaps_storage:
            return self.compliance_gaps_storage[framework]
        return ComplianceGapAnalysis(
            framework=framework,
            asof=datetime.now(UTC),
            gaps=[],
        )

    async def get_control_detail(
        self, framework: str, control_id: str
    ) -> ComplianceControlDetail:
        self._ensure_dashboards_storage()
        key = (framework, control_id)
        if key in self.compliance_controls_storage:
            return self.compliance_controls_storage[key]
        return ComplianceControlDetail(
            control_id=control_id,
            framework=framework,
            title=f"Control {control_id}",
            description="Stub control detail for testing.",
            status="passing",
            score=85.0,
            evidence_package_ids=[],
        )

    # ── Process Knowledge (WI-14) ───────────────────────────────────────────

    def _ensure_knowledge_storage(self) -> None:
        if not hasattr(self, "knowledge_storage"):
            self.knowledge_storage: dict[str, KnowledgeCandidate] = {}
            self.knowledge_decisions: list[dict[str, Any]] = []
            self.knowledge_batch_calls: list[dict[str, Any]] = []

    async def list_knowledge_candidates(
        self, **filters: Any
    ) -> KnowledgeCandidateList:
        self._ensure_knowledge_storage()
        items = list(self.knowledge_storage.values())
        if "status" in filters:
            items = [c for c in items if c.status == filters["status"]]
        if "knowledge_type" in filters:
            items = [c for c in items if c.knowledge_type == filters["knowledge_type"]]
        return KnowledgeCandidateList(items=items, total=len(items))

    async def list_candidates_by_type(
        self, knowledge_type: str
    ) -> KnowledgeCandidateList:
        return await self.list_knowledge_candidates(knowledge_type=knowledge_type)

    async def get_knowledge_candidate(
        self, candidate_id: str
    ) -> KnowledgeCandidate:
        self._ensure_knowledge_storage()
        if candidate_id in self.knowledge_storage:
            return self.knowledge_storage[candidate_id]
        raise KeyError(candidate_id)

    async def approve_candidate(
        self, candidate_id: str, *, rationale: str, decided_by: str
    ) -> KnowledgeCandidate:
        self._ensure_knowledge_storage()
        if candidate_id not in self.knowledge_storage:
            raise KeyError(candidate_id)
        existing = self.knowledge_storage[candidate_id]
        updated = existing.model_copy(
            update={
                "status": "approved",
                "decided_at": datetime.now(UTC),
                "decided_by": decided_by,
                "rationale": rationale,
            }
        )
        self.knowledge_storage[candidate_id] = updated
        self.knowledge_decisions.append(
            {
                "candidate_id": candidate_id,
                "action": "approve",
                "rationale": rationale,
                "decided_by": decided_by,
            }
        )
        return updated

    async def reject_candidate(
        self, candidate_id: str, *, rationale: str, decided_by: str
    ) -> KnowledgeCandidate:
        self._ensure_knowledge_storage()
        if candidate_id not in self.knowledge_storage:
            raise KeyError(candidate_id)
        existing = self.knowledge_storage[candidate_id]
        updated = existing.model_copy(
            update={
                "status": "rejected",
                "decided_at": datetime.now(UTC),
                "decided_by": decided_by,
                "rationale": rationale,
            }
        )
        self.knowledge_storage[candidate_id] = updated
        self.knowledge_decisions.append(
            {
                "candidate_id": candidate_id,
                "action": "reject",
                "rationale": rationale,
                "decided_by": decided_by,
            }
        )
        return updated

    async def modify_candidate(
        self,
        candidate_id: str,
        *,
        modified_yaml: str,
        modified_by: str,
        rationale: str | None = None,
    ) -> KnowledgeCandidate:
        self._ensure_knowledge_storage()
        if candidate_id not in self.knowledge_storage:
            raise KeyError(candidate_id)
        existing = self.knowledge_storage[candidate_id]
        updated = existing.model_copy(
            update={
                "status": "modified",
                "decided_at": datetime.now(UTC),
                "decided_by": modified_by,
                "proposed_yaml": modified_yaml,
                "rationale": rationale,
            }
        )
        self.knowledge_storage[candidate_id] = updated
        self.knowledge_decisions.append(
            {
                "candidate_id": candidate_id,
                "action": "modify",
                "modified_yaml": modified_yaml,
                "modified_by": modified_by,
                "rationale": rationale,
            }
        )
        return updated

    async def batch_process_candidates(
        self,
        *,
        candidate_ids: list[str],
        action: str,
        rationale: str,
        decided_by: str,
    ) -> KnowledgeBatchResult:
        self._ensure_knowledge_storage()
        self.knowledge_batch_calls.append(
            {
                "candidate_ids": list(candidate_ids),
                "action": action,
                "rationale": rationale,
                "decided_by": decided_by,
            }
        )
        successful = 0
        failed = 0
        results: list[dict[str, Any]] = []
        for cid in candidate_ids:
            if cid not in self.knowledge_storage:
                results.append({"candidate_id": cid, "status": "not_found"})
                failed += 1
                continue
            try:
                if action == "approve":
                    await self.approve_candidate(
                        cid, rationale=rationale, decided_by=decided_by
                    )
                else:
                    await self.reject_candidate(
                        cid, rationale=rationale, decided_by=decided_by
                    )
                results.append({"candidate_id": cid, "status": action + "d"})
                successful += 1
            except Exception as exc:  # noqa: BLE001
                results.append({"candidate_id": cid, "status": "error", "note": str(exc)})
                failed += 1
        return KnowledgeBatchResult(
            results=results, successful=successful, failed=failed
        )

    # ── Outcomes / Economics (WI-15) ────────────────────────────────────────

    def _ensure_outcomes_storage(self) -> None:
        if not hasattr(self, "outcomes_kpis_storage"):
            self.outcomes_kpis_storage: OutcomeKPIs | None = None
            self.outcomes_quality_storage: ComplianceTrends | None = None
            self.outcomes_economics_storage: AgentEconomicsList | None = None
            self.outcomes_forecast_storage: ForecastData | None = None
            self.outcomes_summary_storage: OutcomeSummary | None = None

    async def get_cost_per_outcome(
        self, period_start: str, period_end: str
    ) -> OutcomeKPIs:
        self._ensure_outcomes_storage()
        if self.outcomes_kpis_storage is not None:
            return self.outcomes_kpis_storage
        from datetime import datetime as _dt

        try:
            ps = _dt.fromisoformat(period_start.replace("Z", "+00:00"))
        except ValueError:
            ps = datetime.now(UTC) - timedelta(days=30)
        try:
            pe = _dt.fromisoformat(period_end.replace("Z", "+00:00"))
        except ValueError:
            pe = datetime.now(UTC)
        return OutcomeKPIs(
            period_start=ps,
            period_end=pe,
            total_cost_usd=2500.0,
            total_outcomes=50,
            cost_per_outcome_usd=50.0,
            quality_score=86.0,
            roi_ratio=2.4,
            quality_trend_pp=1.5,
        )

    async def get_quality_trends(
        self, period_start: str, period_end: str
    ) -> ComplianceTrends:
        self._ensure_outcomes_storage()
        if self.outcomes_quality_storage is not None:
            return self.outcomes_quality_storage
        from shared.api_client.models import ComplianceTrendPoint

        now = datetime.now(UTC)
        return ComplianceTrends(
            framework="quality",
            period_days=30,
            points=[
                ComplianceTrendPoint(
                    asof=now - timedelta(days=30 - i),
                    score=80.0 + (i * 0.2),
                )
                for i in range(10)
            ],
        )

    async def get_agent_economics(
        self,
        period_start: str,
        period_end: str,
        *,
        agent: str | None = None,
        workflow: str | None = None,
        project: str | None = None,
    ) -> AgentEconomicsList:
        self._ensure_outcomes_storage()
        if self.outcomes_economics_storage is not None:
            return self.outcomes_economics_storage
        from shared.api_client.models import AgentEconomicsRow

        rows = [
            AgentEconomicsRow(
                agent_name="conductor-builder",
                workflow="implement",
                project="project-a",
                invocations=12,
                total_cost_usd=120.0,
                avg_cost_per_invocation_usd=10.0,
                quality_avg=88.0,
                success_rate=0.95,
            ),
            AgentEconomicsRow(
                agent_name="conductor-architect",
                workflow="design",
                project="project-a",
                invocations=4,
                total_cost_usd=60.0,
                avg_cost_per_invocation_usd=15.0,
                quality_avg=92.0,
                success_rate=1.0,
            ),
        ]
        if agent:
            rows = [r for r in rows if r.agent_name == agent]
        if workflow:
            rows = [r for r in rows if r.workflow == workflow]
        if project:
            rows = [r for r in rows if r.project == project]
        return AgentEconomicsList(items=rows)

    async def get_forecast_data(self, horizon_days: int = 30) -> ForecastData:
        self._ensure_outcomes_storage()
        if self.outcomes_forecast_storage is not None:
            return self.outcomes_forecast_storage
        from shared.api_client.models import ForecastPoint

        now = datetime.now(UTC)
        points = [
            ForecastPoint(
                asof=now + timedelta(days=i),
                cost_mean_usd=100.0 + i * 2.0,
                cost_p10_usd=90.0 + i * 1.8,
                cost_p90_usd=120.0 + i * 2.4,
                quality_mean=85.0 + (i * 0.05),
                quality_p10=82.0 + (i * 0.05),
                quality_p90=88.0 + (i * 0.05),
                confidence=0.7,
            )
            for i in range(min(horizon_days, 10))
        ]
        return ForecastData(
            horizon_days=horizon_days, points=points, generated_at=now
        )

    async def get_outcome_summary(
        self, period_start: str, period_end: str
    ) -> OutcomeSummary:
        self._ensure_outcomes_storage()
        if self.outcomes_summary_storage is not None:
            return self.outcomes_summary_storage
        kpis = await self.get_cost_per_outcome(period_start, period_end)
        economics = await self.get_agent_economics(period_start, period_end)
        forecast = await self.get_forecast_data(horizon_days=14)
        trends = await self.get_quality_trends(period_start, period_end)
        return OutcomeSummary(
            period_start=kpis.period_start,
            period_end=kpis.period_end,
            kpis=kpis,
            top_agents=list(economics.items[:5]),
            forecast=forecast,
            quality_trend=list(trends.points),
        )

    # ── Project Documentation Portal (WI-16) ────────────────────────────────

    def _ensure_projects_storage(self) -> None:
        if not hasattr(self, "projects_storage"):
            self.projects_storage: dict[str, ProjectSummary] = {}
            self.project_docs_storage: dict[str, list[dict[str, Any]]] = {}
            self.project_doc_content_storage: dict[
                tuple[str, str], ProjectDoc
            ] = {}
            self.project_doc_history_storage: dict[
                tuple[str, str], DocVersionList
            ] = {}
            self.project_doc_diff_storage: dict[
                tuple[str, str, str, str], DocDiff
            ] = {}
            self.project_search_storage: SearchResults | None = None
            self.project_zip_calls: list[str] = []

    async def list_projects(self, **filters: Any) -> ProjectList:
        self._ensure_projects_storage()
        items = list(self.projects_storage.values())
        return ProjectList(items=items, total=len(items))

    async def get_project(self, project_id: str) -> ProjectSummary:
        self._ensure_projects_storage()
        if project_id in self.projects_storage:
            return self.projects_storage[project_id]
        raise KeyError(project_id)

    async def list_project_docs(self, project_id: str) -> dict[str, Any]:
        self._ensure_projects_storage()
        nodes = self.project_docs_storage.get(project_id, [])
        return {"items": nodes}

    async def get_project_doc(
        self, project_id: str, doc_path: str
    ) -> ProjectDoc:
        self._ensure_projects_storage()
        key = (project_id, doc_path)
        if key in self.project_doc_content_storage:
            return self.project_doc_content_storage[key]
        raise KeyError(key)

    async def get_project_doc_history(
        self, project_id: str, doc_path: str
    ) -> DocVersionList:
        self._ensure_projects_storage()
        key = (project_id, doc_path)
        if key in self.project_doc_history_storage:
            return self.project_doc_history_storage[key]
        return DocVersionList(project_id=project_id, doc_path=doc_path, items=[])

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
        self._ensure_projects_storage()
        if self.project_search_storage is not None:
            results = self.project_search_storage
            # Apply project_ids filter
            if project_ids is not None:
                allowed = set(project_ids)
                hits = [h for h in results.items if h.project_id in allowed]
                return SearchResults(query=q, items=hits, total=len(hits))
            return results
        return SearchResults(query=q, items=[], total=0)

    async def get_doc_diff(
        self,
        project_id: str,
        doc_path: str,
        from_sha: str,
        to_sha: str,
    ) -> DocDiff:
        self._ensure_projects_storage()
        key = (project_id, doc_path, from_sha, to_sha)
        if key in self.project_doc_diff_storage:
            return self.project_doc_diff_storage[key]
        return DocDiff(
            project_id=project_id,
            doc_path=doc_path,
            from_sha=from_sha,
            to_sha=to_sha,
            diff_text=f"--- a/{doc_path}\n+++ b/{doc_path}\n",
        )

    async def generate_zip_export(self, project_id: str) -> dict[str, Any]:
        self._ensure_projects_storage()
        self.project_zip_calls.append(project_id)
        return {"project_id": project_id, "status": "ready"}


# ─── Convenience builders ───────────────────────────────────────────────────


def build_audit_event(
    *,
    event_id: str,
    audit_type: str = "session.started",
    classification: str = "internal",
    chain_index: int = 1,
    chain_hash: str = "h" + ("0" * 63),
    prev_hash: str = "p" + ("0" * 63),
    user_id: str | None = "alice",
    payload: dict[str, Any] | None = None,
    ts: datetime | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        audit_type=audit_type,
        classification=classification,
        chain_index=chain_index,
        chain_hash=chain_hash,
        prev_hash=prev_hash,
        user_id=user_id,
        ts=ts or _NOW,
        payload=payload or {},
    )


def build_evidence_package(
    *,
    package_id: str,
    title: str = "Sample evidence",
    version: str = "v1",
    classification: str = "confidential",
) -> EvidencePackage:
    return EvidencePackage(
        package_id=package_id,
        title=title,
        version=version,
        classification=classification,
        signed_by="compliance-svc",
        created_at=_NOW,
        updated_at=_NOW,
        signature_algorithm="Ed25519",
    )


def build_human_gate(
    *,
    gate_id: str,
    title: str = "Pending decision",
    classification: str = "confidential",
    triggered_by: str | None = None,
    status_str: str = "pending",
    sla_in_seconds: int = 7200,
    evidence_package_ids: list[str] | None = None,
    payload: dict[str, Any] | None = None,
) -> HumanGate:
    return HumanGate(
        gate_id=gate_id,
        title=title,
        classification=classification,
        status=status_str,
        triggered_by=triggered_by,
        requested_at=_NOW,
        sla_deadline=_NOW + timedelta(seconds=sla_in_seconds),
        evidence_package_ids=evidence_package_ids or [],
        payload=payload or {},
    )


def build_engagement(
    *,
    engagement_id: str = "ENG-2026-001",
    auditor_email: str = "auditor@firm.example",
    state: str = "active",
    days_remaining: int = 30,
    allowed_artifact_types: list[str] | None = None,
) -> AuditorEngagement:
    now = datetime.now(UTC)
    return AuditorEngagement(
        engagement_id=engagement_id,
        auditor_email=auditor_email,
        auditor_sub="auditor-test-1",
        engagement_start=now - timedelta(days=1),
        engagement_end=now + timedelta(days=days_remaining),
        date_range_start=now - timedelta(days=365),
        date_range_end=now,
        allowed_artifact_types=allowed_artifact_types
        or ["audit_event", "evidence_package", "gate_decision"],
        state=state,
        created_at=now - timedelta(days=2),
    )


def build_dsr(
    *,
    request_id: str = "DSR-0001",
    request_type: str = "access",
    status: str = "received",
    submitted_by: str | None = None,
    submitted_days_ago: int = 0,
    subject_email: str | None = "subject@example.com",
    subject_name: str | None = "Subject Name",
    source: str = "internal",
) -> DsrRequest:
    submitted_at = datetime.now(UTC) - timedelta(days=submitted_days_ago)
    return DsrRequest(
        request_id=request_id,
        request_type=request_type,
        status=status,
        submitted_at=submitted_at,
        submitted_by=submitted_by,
        subject_email=subject_email,
        subject_name=subject_name,
        source=source,
    )


def build_incident(
    *,
    incident_id: str = "INC-0001",
    severity: str = "high",
    status: str = "open",
    triggered_hours_ago: int = 0,
    title: str = "Suspicious access",
    affected_session_ids: list[str] | None = None,
    source: str = "manual",
) -> Incident:
    triggered_at = datetime.now(UTC) - timedelta(hours=triggered_hours_ago)
    return Incident(
        incident_id=incident_id,
        title=title,
        severity=severity,
        status=status,
        detected_at=triggered_at,
        triggered_at=triggered_at,
        affected_session_ids=affected_session_ids or [],
        source=source,
    )


def build_model_card(
    *,
    model_id: str = "claude-opus-4.7",
    name: str = "Claude Opus 4.7",
    family: str = "anthropic",
    version: str = "4.7",
    risk_tier: int = 3,
    next_review_days_ahead: int | None = 365,
    intended_use: str = "Compliance reasoning, document review",
    prohibited_use: str = "Direct PII processing without DPIA",
) -> ModelCard:
    next_review = (
        datetime.now(UTC) + timedelta(days=next_review_days_ahead)
        if next_review_days_ahead is not None
        else None
    )
    return ModelCard(
        model_id=model_id,
        name=name,
        family=family,
        version=version,
        framework="anthropic-api",
        vendor="Anthropic",
        intended_use=intended_use,
        prohibited_use=prohibited_use,
        risk_tier=risk_tier,
        last_validated_at=datetime.now(UTC) - timedelta(days=30),
        next_review_date=next_review,
        review_status="up_to_date",
    )


def build_report(
    *,
    report_id: str = "RPT-0001",
    report_type: str = "sox_attestation",
    stage: str = "draft",
    created_by: str = "officer-1",
) -> RegulatoryReport:
    return RegulatoryReport(
        report_id=report_id,
        report_type=report_type,
        stage=stage,
        created_at=datetime.now(UTC),
        created_by=created_by,
    )


def build_knowledge_candidate(
    *,
    candidate_id: str = "cand-001",
    knowledge_type: str = "rule",
    domain: str = "compliance",
    status: str = "pending",
    proposed_yaml: str = "rule:\n  id: r1\n  if: x\n  then: y\n",
    existing_yaml: str | None = None,
) -> KnowledgeCandidate:
    from shared.api_client.models import KnowledgeSource

    return KnowledgeCandidate(
        candidate_id=candidate_id,
        knowledge_type=knowledge_type,
        domain=domain,
        proposed_yaml=proposed_yaml,
        existing_yaml=existing_yaml,
        status=status,
        source=KnowledgeSource(
            source_type="trajectory",
            source_id="traj-1",
            snippet="example snippet",
            confidence=0.85,
        ),
        created_at=datetime.now(UTC),
    )


def build_project_summary(
    *,
    project_id: str = "PRJ-001",
    name: str = "Test project",
    tier: str = "STANDARD",
    status: str = "active",
    doc_count: int = 4,
) -> ProjectSummary:
    return ProjectSummary(
        project_id=project_id,
        name=name,
        tier=tier,
        status=status,
        last_activity=datetime.now(UTC),
        doc_count=doc_count,
    )


def build_project_doc(
    *,
    project_id: str = "PRJ-001",
    path: str = "requirements/brd.md",
    name: str = "BRD",
    category: str = "requirements",
    doc_type: str = "markdown",
    content: str = "# Heading\n\nBody.",
    rendered_html: str | None = None,
) -> ProjectDoc:
    return ProjectDoc(
        project_id=project_id,
        path=path,
        name=name,
        category=category,
        doc_type=doc_type,
        content=content,
        rendered_html=rendered_html,
        last_modified=datetime.now(UTC),
        last_author="alice",
    )


__all__ = [
    "FakeComplianceClient",
    "build_audit_event",
    "build_evidence_package",
    "build_human_gate",
    "build_engagement",
    "build_dsr",
    "build_incident",
    "build_model_card",
    "build_report",
    "build_knowledge_candidate",
    "build_project_summary",
    "build_project_doc",
]
