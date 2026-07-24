"""Pydantic response models for the compliance service REST API.

These mirror PRD-18's contract. Each model is permissive (extra="allow") so
that minor schema additions on the service side don't break portal reads.
Builder MUST reconcile these with the live service spec at integration time.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _Base(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=False, protected_namespaces=())


# ─── Audit ───────────────────────────────────────────────────────────────────


class AuditEvent(_Base):
    event_id: str
    audit_type: str
    user_id: str | None = None
    classification: str | None = None
    ts: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    chain_index: int | None = None
    chain_hash: str | None = None
    prev_hash: str | None = None


class AuditEventList(_Base):
    items: list[AuditEvent] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


class HashChainVerification(_Base):
    ok: bool
    from_index: int
    to_index: int
    mismatched_at: int | None = None
    note: str | None = None


# ─── Evidence ────────────────────────────────────────────────────────────────


class EvidencePackage(_Base):
    package_id: str
    title: str
    version: str
    classification: str | None = None
    signed_by: str | None = None
    created_at: datetime
    updated_at: datetime | None = None
    signature_algorithm: str | None = None


class EvidencePackageList(_Base):
    items: list[EvidencePackage] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


# ─── Human Gates ─────────────────────────────────────────────────────────────


class HumanGate(_Base):
    gate_id: str
    title: str
    classification: str | None = None
    status: str
    triggered_by: str | None = None
    requested_at: datetime
    sla_deadline: datetime | None = None
    evidence_package_ids: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    decision: str | None = None
    decided_by: str | None = None
    decided_at: datetime | None = None
    rationale: str | None = None


class HumanGateList(_Base):
    items: list[HumanGate] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


class GateDecisionReceipt(_Base):
    """Signed decision receipt returned by compliance service after a gate decision."""

    receipt_id: str
    gate_id: str
    decision: str  # approve | deny | escalate
    rationale: str
    decided_by: str
    decided_at: datetime
    signature: str | None = None  # Ed25519, base64
    signing_key_id: str | None = None
    evidence_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    escalate_to_role: str | None = None


# ─── Evidence — versions, diff, download metadata ──────────────────────────


class EvidenceVersion(_Base):
    package_id: str
    version: str
    created_at: datetime
    created_by: str | None = None
    note: str | None = None
    artifact_hash: str | None = None


class EvidenceVersionList(_Base):
    package_id: str
    items: list[EvidenceVersion] = Field(default_factory=list)


class EvidenceDiff(_Base):
    """Server-computed text diff between two versions of a package manifest."""

    package_id: str
    from_version: str
    to_version: str
    diff_text: str  # unified diff
    binary: bool = False  # if true, diff_text is a placeholder note


class EvidenceSignatureStatus(_Base):
    package_id: str
    version: str
    valid: bool
    algorithm: str = "Ed25519"
    signing_key_id: str | None = None
    signed_at: datetime | None = None
    note: str | None = None


class EvidenceDownload(_Base):
    """Metadata returned alongside a download — bytes streamed separately."""

    package_id: str
    version: str
    filename: str
    media_type: str
    size_bytes: int
    download_url: str | None = None  # presigned, optional
    artifact_hash: str | None = None


# ─── Auditor Engagements (REQ-CPL-033/034/035) ─────────────────────────────


class AuditorEngagement(_Base):
    engagement_id: str
    auditor_email: str
    auditor_sub: str | None = None
    engagement_start: datetime
    engagement_end: datetime
    date_range_start: datetime
    date_range_end: datetime
    allowed_artifact_types: list[str] = Field(default_factory=list)
    allowed_project_ids: list[str] | None = None
    state: str = "active"  # active | revoked | expired
    created_by: str | None = None
    created_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoked_reason: str | None = None


class AuditorEngagementList(_Base):
    items: list[AuditorEngagement] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


class EngagementAccessLogEntry(_Base):
    engagement_id: str
    artifact_type: str
    artifact_id: str
    accessed_at: datetime
    ip: str | None = None
    user_agent: str | None = None
    action: str = "view"  # view | download | export


class EngagementAccessLog(_Base):
    engagement_id: str
    items: list[EngagementAccessLogEntry] = Field(default_factory=list)
    next_cursor: str | None = None


# ─── DSR ─────────────────────────────────────────────────────────────────────


class DsrRequest(_Base):
    """A DSR record. Status string is one of:
        received | identity_pending | identity_insufficient | identity_rejected |
        verified | processing | evidence_generated | delivered | closed | rejected
    """

    request_id: str
    request_type: str  # access|portability|erasure|rectification|objection|restriction|automated_decision_review
    status: str
    submitted_at: datetime
    sla_deadline: datetime | None = None
    closed_at: datetime | None = None
    submitted_by: str | None = None  # for SoD enforcement (AMD-01)
    subject_email: str | None = None
    subject_name: str | None = None
    source: str = "internal"  # internal|public|paper|phone
    # Optional supplemental fields (compliance service authoritative)
    identity_proof_id: str | None = None
    notes: list[dict[str, Any]] = Field(default_factory=list)
    transitions: list[dict[str, Any]] = Field(default_factory=list)
    delivery_tokens: list[dict[str, Any]] = Field(default_factory=list)
    evidence_package_id: str | None = None


class DsrRequestList(_Base):
    items: list[DsrRequest] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


class DsrTransitionResult(_Base):
    request_id: str
    from_status: str
    to_status: str
    transitioned_at: datetime
    transitioned_by: str | None = None
    notes: str | None = None
    invalidated_token_count: int = 0  # AMD-12: tokens invalidated on close


class DsrEvidenceJob(_Base):
    """Returned by generate_dsr_evidence — either a job (202) or evidence package (200)."""

    request_id: str
    job_id: str | None = None
    status: str = "pending"  # pending | running | complete | failed
    evidence_package_id: str | None = None


class DsrDeliveryToken(_Base):
    request_id: str
    token: str
    expires_at: datetime
    package_id: str
    version: str


class DsrPublicStatus(_Base):
    """Sanitized status returned to public submitter (no PII)."""

    reference: str
    request_type: str
    current_status: str
    submitted_at: datetime
    deadline_at: datetime | None = None
    days_remaining: float | None = None
    last_update_at: datetime | None = None


class DsrPublicSubmissionResult(_Base):
    """Result of public submission — reference number returned to submitter."""

    reference: str
    request_id: str
    submitted_at: datetime
    identity_proof_status: str = "pending"  # pending | clean | infected | unscannable


class IdentityProofScanResult(_Base):
    """AMD-26 — malware scan verdict for uploaded identity proof."""

    proof_id: str
    scan_status: str  # clean | infected | unscannable | pending
    scan_engine: str | None = None
    scan_signature_id: str | None = None
    reason: str | None = None


# ─── Incidents ───────────────────────────────────────────────────────────────


class IncidentNote(_Base):
    note_id: str
    author_sub: str
    author_name: str | None = None
    created_at: datetime
    content: str  # raw markdown
    rendered_html: str | None = None  # server-rendered (AMD-19)
    tags: list[str] = Field(default_factory=list)


class IncidentNotification(_Base):
    notification_id: str
    recipient: str
    channel: str  # email | regulator_portal | phone | fax | in_person
    sent_at: datetime
    confirmation_id: str | None = None
    status: str = "pending"  # pending | sent | acknowledged | failed


class Incident(_Base):
    incident_id: str
    title: str | None = None
    severity: str
    status: str  # open | investigating | contained | closed
    detected_at: datetime
    triggered_at: datetime | None = None  # 72h clock anchor
    notification_due_at: datetime | None = None
    closed_at: datetime | None = None
    notes: list[IncidentNote] = Field(default_factory=list)
    notifications: list[IncidentNotification] = Field(default_factory=list)
    affected_session_ids: list[str] = Field(default_factory=list)
    source: str = "manual"  # manual | guardian_terminate
    report_id: str | None = None


class IncidentList(_Base):
    items: list[Incident] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


# ─── Model Cards ─────────────────────────────────────────────────────────────


class ModelCardResponsible(_Base):
    person_sub: str
    name: str
    email: str
    role: str  # primary | secondary | business_owner | technical_owner


class ModelCardReview(_Base):
    review_id: str
    model_id: str
    state: str  # scheduled | evidence_assembly | reviewer_assigned | decision | signed_off
    scheduled_for: datetime | None = None
    reviewer_sub: str | None = None
    decision: str | None = None  # approve | defer | escalate
    rationale: str | None = None
    signed_at: datetime | None = None
    signed_by: str | None = None
    signature: str | None = None
    signing_key_id: str | None = None
    evidence_package_ids: list[str] = Field(default_factory=list)


class ModelCard(_Base):
    model_id: str
    name: str
    family: str | None = None
    version: str
    framework: str | None = None
    vendor: str | None = None
    deployment_scope: str | None = None
    intended_use: str | None = None
    prohibited_use: str | None = None
    risk_tier: int | None = None  # NY DFS Part 500 1-4
    last_validated_at: datetime | None = None
    bias_assessment_summary: str | None = None
    bias_evidence_package_id: str | None = None
    next_review_date: datetime | None = None
    review_status: str | None = None
    responsibles: list[ModelCardResponsible] = Field(default_factory=list)
    reviews: list[ModelCardReview] = Field(default_factory=list)


# ─── Regulatory Reports (REQ-CPL-022..026) ───────────────────────────────────


class ReportDelivery(_Base):
    delivery_id: str
    report_id: str
    channel: str  # email | secure_download | regulator_portal
    recipient: str
    delivered_at: datetime
    confirmation_receipt: str | None = None


class RegulatoryReport(_Base):
    report_id: str
    report_type: str  # sox_attestation | nydfs_part500 | eu_ai_act_conformity | naic_adverse_action
    stage: str  # draft | review | approved | signed | delivered
    period_start: datetime | None = None
    period_end: datetime | None = None
    triggering_event_id: str | None = None
    high_risk_system_change_id: str | None = None
    scope_notes: str | None = None
    created_at: datetime
    created_by: str
    reviewed_by: str | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    signed_at: datetime | None = None
    signed_by: str | None = None
    signature: str | None = None  # Ed25519 base64
    signing_key_id: str | None = None
    deliveries: list[ReportDelivery] = Field(default_factory=list)
    transitions: list[dict[str, Any]] = Field(default_factory=list)


class RegulatoryReportList(_Base):
    items: list[RegulatoryReport] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


# ─── Compliance Dashboards (WI-13, REQ-CPL-027/028) ─────────────────────────


class ComplianceDomainScore(_Base):
    domain: str
    score: float  # 0..100


class ComplianceScores(_Base):
    framework: str  # iso42001 | eu_ai_act | owasp_agentic | soc2 | iso27001 | glba
    overall_score: float
    asof: datetime
    domain_scores: list[ComplianceDomainScore] = Field(default_factory=list)
    regression_flag: bool = False


class ComplianceTrendPoint(_Base):
    asof: datetime
    score: float


class ComplianceTrends(_Base):
    framework: str
    period_days: int
    points: list[ComplianceTrendPoint] = Field(default_factory=list)


class ComplianceGap(_Base):
    control_id: str
    title: str
    impact: str  # high | medium | low
    status: str  # open | in_progress | closed
    assignee: str | None = None
    due_date: datetime | None = None
    last_update: datetime | None = None
    evidence_required: str | None = None


class ComplianceGapAnalysis(_Base):
    framework: str
    asof: datetime
    gaps: list[ComplianceGap] = Field(default_factory=list)


class ComplianceControlDetail(_Base):
    control_id: str
    framework: str
    title: str
    description: str | None = None
    status: str  # passing | partial | failing | not_assessed
    score: float | None = None
    evidence_package_ids: list[str] = Field(default_factory=list)
    last_evaluated_at: datetime | None = None
    notes: str | None = None


# ─── Process Knowledge (WI-14, REQ-CPL-029/030) ─────────────────────────────


class KnowledgeSource(_Base):
    source_type: str  # trajectory | session | document
    source_id: str
    snippet: str | None = None
    confidence: float = 1.0


class KnowledgeCandidate(_Base):
    candidate_id: str
    knowledge_type: str  # rule | decision_tree | sop | edge_case
    domain: str
    proposed_yaml: str
    existing_yaml: str | None = None
    status: str  # pending | approved | rejected | modified
    assigned_to: str | None = None
    source: KnowledgeSource
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    rationale: str | None = None


class KnowledgeCandidateList(_Base):
    items: list[KnowledgeCandidate] = Field(default_factory=list)
    next_cursor: str | None = None
    total: int | None = None


class KnowledgeBatchResult(_Base):
    results: list[dict[str, Any]] = Field(default_factory=list)
    successful: int = 0
    failed: int = 0


# ─── Outcomes / Economics (WI-15, REQ-CPL-031/032) ──────────────────────────


class OutcomeKPIs(_Base):
    period_start: datetime
    period_end: datetime
    total_cost_usd: float
    total_outcomes: int
    cost_per_outcome_usd: float
    quality_score: float
    roi_ratio: float
    quality_trend_pp: float = 0.0


class AgentEconomicsRow(_Base):
    agent_name: str
    workflow: str | None = None
    project: str | None = None
    invocations: int
    total_cost_usd: float
    avg_cost_per_invocation_usd: float
    quality_avg: float
    success_rate: float


class AgentEconomicsList(_Base):
    items: list[AgentEconomicsRow] = Field(default_factory=list)
    period_start: datetime | None = None
    period_end: datetime | None = None


class ForecastPoint(_Base):
    asof: datetime
    cost_mean_usd: float
    cost_p10_usd: float
    cost_p90_usd: float
    quality_mean: float
    quality_p10: float
    quality_p90: float
    confidence: float = 0.5


class ForecastData(_Base):
    horizon_days: int
    points: list[ForecastPoint] = Field(default_factory=list)
    generated_at: datetime


class OutcomeSummary(_Base):
    period_start: datetime
    period_end: datetime
    kpis: OutcomeKPIs
    top_agents: list[AgentEconomicsRow] = Field(default_factory=list)
    forecast: ForecastData | None = None
    quality_trend: list[ComplianceTrendPoint] = Field(default_factory=list)


# ─── Project Documentation Portal (WI-16, REQ-CPL-040..044) ─────────────────


class ProjectSummary(_Base):
    project_id: str
    name: str
    tier: str  # TRIVIAL | MINOR | STANDARD | MAJOR
    status: str  # active | completed | archived
    last_activity: datetime
    doc_count: int = 0


class ProjectList(_Base):
    items: list[ProjectSummary] = Field(default_factory=list)
    total: int | None = None


class DocNode(_Base):
    path: str
    name: str
    category: str  # requirements | architecture | implementation | testing | compliance | operations
    doc_type: str  # markdown | openapi | report | sbom | other
    last_modified: datetime
    last_author: str | None = None
    children: list["DocNode"] = Field(default_factory=list)


class ProjectDoc(_Base):
    project_id: str
    path: str
    name: str
    category: str
    doc_type: str
    content: str  # raw markdown or json
    rendered_html: str | None = None  # server-rendered for markdown
    last_modified: datetime
    last_author: str | None = None


class DocVersion(_Base):
    version_id: str  # git commit SHA
    author: str
    timestamp: datetime
    message: str


class DocVersionList(_Base):
    project_id: str
    doc_path: str
    items: list[DocVersion] = Field(default_factory=list)


class DocDiff(_Base):
    project_id: str
    doc_path: str
    from_sha: str
    to_sha: str
    diff_text: str  # unified diff format


class SearchHit(_Base):
    project_id: str
    doc_path: str
    title: str
    snippet: str
    score: float
    last_modified: datetime
    author: str | None = None


class SearchResults(_Base):
    query: str
    items: list[SearchHit] = Field(default_factory=list)
    total: int | None = None


# ─── Generic ─────────────────────────────────────────────────────────────────


class AuditRecordResult(_Base):
    event_id: str
    ts: datetime
    accepted: bool = True


__all__ = [
    "AuditEvent",
    "AuditEventList",
    "HashChainVerification",
    "EvidencePackage",
    "EvidencePackageList",
    "EvidenceVersion",
    "EvidenceVersionList",
    "EvidenceDiff",
    "EvidenceSignatureStatus",
    "EvidenceDownload",
    "HumanGate",
    "HumanGateList",
    "GateDecisionReceipt",
    "DsrRequest",
    "DsrRequestList",
    "DsrTransitionResult",
    "DsrEvidenceJob",
    "DsrDeliveryToken",
    "DsrPublicStatus",
    "DsrPublicSubmissionResult",
    "IdentityProofScanResult",
    "Incident",
    "IncidentList",
    "IncidentNote",
    "IncidentNotification",
    "ModelCard",
    "ModelCardResponsible",
    "ModelCardReview",
    "RegulatoryReport",
    "RegulatoryReportList",
    "ReportDelivery",
    "AuditRecordResult",
    "AuditorEngagement",
    "AuditorEngagementList",
    "EngagementAccessLogEntry",
    "EngagementAccessLog",
    # WI-13 Compliance Dashboards
    "ComplianceDomainScore",
    "ComplianceScores",
    "ComplianceTrendPoint",
    "ComplianceTrends",
    "ComplianceGap",
    "ComplianceGapAnalysis",
    "ComplianceControlDetail",
    # WI-14 Process Knowledge
    "KnowledgeSource",
    "KnowledgeCandidate",
    "KnowledgeCandidateList",
    "KnowledgeBatchResult",
    # WI-15 Outcomes
    "OutcomeKPIs",
    "AgentEconomicsRow",
    "AgentEconomicsList",
    "ForecastPoint",
    "ForecastData",
    "OutcomeSummary",
    # WI-16 Project Docs
    "ProjectSummary",
    "ProjectList",
    "DocNode",
    "ProjectDoc",
    "DocVersion",
    "DocVersionList",
    "DocDiff",
    "SearchHit",
    "SearchResults",
]
