# API Reference

Complete reference for all 81 internal portal routes and 8 public DSR portal routes.

## Internal Portal (81 routes)

### Health Check (2 routes)

```
GET /healthz
  • No authentication required
  • Response: {"status": "ok", "version": "0.1.0"}

GET /readiness
  • Checks database, Redis, Qdrant connectivity
  • Response: {"ready": true, "timestamp": "2026-04-27T..."}
```

### Authentication (auth.build_auth_router(), 5 routes)

```
GET /auth/login
  • Redirect to OIDC issuer
  • Sets code_verifier, nonce
  • Role: any

GET /auth/callback
  • OIDC callback handler
  • Validates authorization code
  • Rotates session ID (AMD-15)
  • Extracts groups → roles mapping
  • Role: any

POST /auth/logout
  • Invalidate session
  • Clear session cookie
  • Role: authenticated

POST /auth/mfa/challenge
  • Issue MFA challenge for sensitive operations
  • Bind nonce to (user_sub, resource_id)
  • Max lifetime 60s (AMD-03)
  • Role: authenticated

POST /auth/mfa/verify
  • Verify TOTP/WebAuthn response
  • Consume nonce (replay protection)
  • Role: authenticated
```

### Audit Explorer (8 routes, WI-04)

```
GET /audit/search
  Query params: query, limit, offset, sort
  • Search audit logs by keyword
  • Role: officer, auditor

GET /audit/list
  Query params: limit, offset, order_by
  • List all audit events with filters
  • Role: officer, auditor

GET /audit/<event_id>
  • Get single audit event details
  • Role: officer, auditor

GET /audit/<event_id>/related
  • Get related events (same resource, timeframe)
  • Role: officer, auditor

POST /audit/<event_id>/export
  Body: {format: "json" | "csv", recipients: ["email@org"]}
  • Export audit event(s) to recipients
  • Role: officer

GET /audit/<event_id>/verify
  Query params: hash_algorithm
  • Verify audit event integrity (AMD-07)
  • Returns: {verified: bool, hash: string}
  • Role: auditor

POST /audit/bulk-download
  Body: {event_ids: [...], format: "zip" | "tar.gz"}
  • Download multiple events as archive
  • Role: officer, auditor

GET /audit/compliance-report
  Query params: start_date, end_date, framework (soc2|iso27001|gdpr)
  • Generate compliance evidence report
  • Role: officer
```

### Evidence Package Library (6 routes, WI-05)

```
GET /evidence
  Query params: limit, offset, status
  • List evidence packages with filter
  • Role: officer, auditor

GET /evidence/<evidence_id>
  • Get evidence package metadata
  • Role: officer, auditor

GET /evidence/<evidence_id>/download
  Header: Authorization: Bearer <auditor_token>
  Query params: watermark (true|false), format (pdf|json)
  • Download evidence (watermarked if auditor)
  • Embeds metadata (AMD-06)
  • Role: officer, auditor

POST /evidence/<evidence_id>/verify
  Body: {hash: string, hash_algorithm: "sha256"}
  • Verify evidence hash integrity
  • Returns: {verified: bool, hash: string}
  • Role: auditor

GET /evidence/<evidence_id>/audit-trail
  • Get complete audit trail for this evidence
  • Shows who accessed, when, why
  • Role: officer

POST /evidence/<evidence_id>/lock
  • Lock evidence to prevent further download
  • Returns: {locked: true, locked_at: "..."}
  • Role: admin
```

### Gate Decision Workspace (12 routes, WI-06)

```
GET /gates
  Query params: status (pending|approved|rejected), priority
  • List pending gate decisions
  • Role: officer

GET /gates/<gate_id>
  • Get single gate decision detail
  • Shows linked evidence, stakeholders, comments
  • Role: officer

POST /gates/<gate_id>/detail-page-rendered
  • Record that detail page rendered
  • Issues decision_nonce (AMD-03)
  • Returns: {nonce: string, expires_at: "..."}
  • Role: officer

POST /gates/<gate_id>/mfa/challenge
  Body: {decision_nonce: string}
  • Initiate MFA step-up for decision
  • Returns MFA prompt type (totp|webauthn)
  • Role: officer

POST /gates/<gate_id>/mfa/verify
  Body: {mfa_code: string, nonce: string}
  • Verify MFA response
  • Returns: {verified: true, session_mfa_verified: "..."}
  • Role: officer

POST /gates/<gate_id>/decide
  Body: {decision: "approve"|"reject", evidence_links: [...], notes: string, nonce: string}
  Header: x-decision-nonce (alternative to body nonce)
  • Submit gate decision
  • Validates nonce + MFA verification + SoD
  • Emits gate.decision_submitted audit
  • Role: officer (SoD: submitter ≠ requester)

GET /gates/<gate_id>/comments
  • List decision comments
  • Role: officer

POST /gates/<gate_id>/comment
  Body: {text: string}
  • Add comment to gate
  • Role: officer

GET /gates/<gate_id>/stakeholder-notifications
  • List stakeholders notified
  • Role: officer

POST /gates/<gate_id>/notify-stakeholder
  Body: {stakeholder_email: string, subject: string, message: string}
  • Send notification to stakeholder
  • Role: officer

GET /gates/<gate_id>/sod-check
  • Verify separation of duties
  • Returns: {valid: bool, submitter: string, requester: string}
  • Role: officer

GET /gates/bulk-action
  Query params: action, gate_ids
  • Bulk approve/reject decisions
  • Role: officer
```

### Auditor Access Controls (7 routes, WI-07)

```
GET /admin/auditors
  • List all auditor tokens (admin portal)
  • Role: admin

POST /admin/auditors/token
  Body: {auditor_name: string, engagement_id: string, scope: {evidence_ids: [...]}, expires_in_days: 30}
  • Create new auditor access token
  • Time-limited (default 30 days)
  • Scoped to specific evidence
  • Role: admin

GET /admin/auditors/<token_id>
  • Get token details (scope, expiry, usage stats)
  • Role: admin

POST /admin/auditors/<token_id>/revoke
  • Revoke auditor token immediately
  • Role: admin

GET /admin/auditors/<token_id>/usage
  • View token usage statistics
  • Role: admin

GET /admin/auditors/audit-trail
  • Audit trail of token creation/revocation/usage
  • Role: admin

POST /admin/auditors/<token_id>/extend
  Body: {extend_days: 30}
  • Extend token expiry (max 30 additional days)
  • Role: admin
```

### DSR Management (9 routes, WI-08)

```
GET /dsr
  Query params: status, priority, assigned_to
  • List internal DSR records
  • Role: officer

GET /dsr/<dsr_id>
  • Get DSR detail (status, identity verification, evidence)
  • Role: officer

POST /dsr/<dsr_id>/assign
  Body: {reviewer_email: string}
  • Assign DSR to reviewer
  • Role: officer

POST /dsr/<dsr_id>/status
  Body: {new_status: "identity_pending"|"processing"|"completed"|"rejected"}
  • Update DSR status (triggers state machine, AMD-01)
  • Role: officer

GET /dsr/<dsr_id>/identity/review
  • Get identity verification details
  • Shows uploaded document image, extraction data
  • Role: officer

POST /dsr/<dsr_id>/identity/verify
  Body: {decision: "approved"|"rejected", reviewer_notes: string}
  • Approve/reject identity verification
  • For high-sensitivity requests: requires supervisor sign-off
  • Role: officer

GET /dsr/<dsr_id>/evidence
  • Get evidence packages linked to this DSR
  • Role: officer

POST /dsr/<dsr_id>/evidence/package
  Body: {evidence_ids: [...]}
  • Create evidence package for DSR
  • Role: officer

GET /dsr/<dsr_id>/sla-status
  • Get SLA tracking (GDPR 30-day window)
  • Returns: {days_remaining: 5, deadline: "2026-05-27T..."}
  • Role: officer
```

### Incident Management (6 routes, WI-10)

```
GET /incidents
  Query params: status, priority, sla_status
  • List security incidents
  • Role: officer

POST /incidents
  Body: {title: string, description: string, severity: "critical"|"high"|"medium"|"low", affected_systems: [...]}
  • Create new incident
  • Triggers SLA clock (72h for NY DFS, AMD-...-Incident)
  • Role: officer

GET /incidents/<incident_id>
  • Get incident detail
  • Shows timeline, remediation progress, SLA status
  • Role: officer

POST /incidents/<incident_id>/assign
  Body: {assigned_to_email: string}
  • Assign incident to responder
  • Role: officer

POST /incidents/<incident_id>/remediation
  Body: {action: string, status: "in_progress"|"completed", evidence: string}
  • Record remediation action
  • Emits incident.remediation_recorded audit
  • Role: officer

GET /incidents/<incident_id>/sla-status
  • Get SLA tracking (72-hour clock)
  • Returns: {hours_remaining: 48, notification_required: false}
  • Role: officer
```

### Model Card Registry (7 routes, WI-11)

```
GET /model-cards
  Query params: status, requires_review
  • List models with card metadata
  • Role: officer, sme

GET /model-cards/<model_id>
  • Get model card detail (version, approvers, last review)
  • Role: officer, sme

POST /model-cards/<model_id>/sign-off
  Body: {signature_nonce: string}
  • Initiate MFA for sign-off (AMD-03)
  • Returns MFA challenge
  • Role: officer

POST /model-cards/<model_id>/sign-off/verify
  Body: {mfa_code: string, nonce: string}
  • Verify MFA and record sign-off
  • Role: officer

GET /model-cards/<model_id>/review-queue
  • List pending expert reviews for this model
  • Role: sme

POST /model-cards/<model_id>/review
  Body: {decision: "approved"|"needs_revision", notes: string}
  • Record SME review decision
  • Role: sme

GET /model-cards/<model_id>/audit-trail
  • Complete audit trail (creation, reviews, sign-offs)
  • Role: officer
```

### Regulatory Report Generation (6 routes, WI-12)

```
GET /reports
  Query params: framework (soc2|iso|gdpr|ny-dfs), status
  • List generated reports
  • Role: officer

POST /reports/generate
  Body: {framework: string, period: "quarterly"|"annual", include_evidence: bool}
  • Generate regulatory report
  • Role: officer

GET /reports/<report_id>
  • Get report metadata (generated_at, framework, signed_at)
  • Role: officer

POST /reports/<report_id>/sign
  Body: {signature_nonce: string}
  • Initiate MFA for signing (AMD-03)
  • Role: officer

POST /reports/<report_id>/sign/verify
  Body: {mfa_code: string, nonce: string}
  • Verify MFA and sign report with Ed25519 (AMD-04)
  • Generates JWKS delivery bundle
  • Role: officer

GET /reports/<report_id>/download
  Query params: format (pdf|zip_bundle), include_jwks
  • Download signed report (PDF) or delivery bundle (ZIP with JWKS)
  • Role: officer
```

### Compliance Dashboards (5 routes, WI-13)

```
GET /dashboards/sla-compliance
  Query params: period (7d|30d|90d)
  • SLA compliance heatmap
  • DSR: GDPR 30-day window
  • Incidents: NY DFS 72-hour clock
  • Role: officer

GET /dashboards/risk
  Query params: framework (soc2|iso|gdpr)
  • Risk heatmap by control
  • Shows remediation progress
  • Role: officer

GET /dashboards/remediation-pipeline
  Query params: status
  • Remediation progress tracking
  • Shows blocked, in-progress, completed actions
  • Role: officer

GET /dashboards/evidence-coverage
  Query params: framework
  • Evidence package coverage by control
  • Shows gaps requiring additional evidence
  • Role: officer

GET /dashboards/audit-summary
  Query params: period
  • Audit activity summary (events/day, anomalies)
  • Role: officer
```

### Process Knowledge Verification (5 routes, WI-14)

```
GET /knowledge/candidates
  Query params: status (pending|approved|rejected), category
  • List process knowledge candidates (from trajectory mining)
  • Role: sme

GET /knowledge/candidates/<candidate_id>
  • Get knowledge candidate detail
  • Shows proposed rule/decision tree, source trajectories
  • Role: sme

POST /knowledge/candidates/<candidate_id>/review
  Body: {decision: "approve"|"reject"|"modify", notes: string, modifications: {}}
  • Record SME review decision
  • Role: sme

GET /knowledge/approved
  • List approved knowledge items
  • Role: sme, officer

POST /knowledge/export
  Body: {format: "json"|"yaml", include_metadata: bool}
  • Export approved knowledge base
  • Role: officer
```

### Outcome Economics (4 routes, WI-15)

```
GET /outcomes/cost
  Query params: period (mtd|qtd|ytd), breakdown (by_system|by_control)
  • Cost analysis (labor, infrastructure, third-party)
  • Role: viewer

GET /outcomes/timeline
  Query params: period
  • Timeline analysis (deployment velocity, SLA achievement)
  • Role: viewer

GET /outcomes/success-metrics
  • KPI dashboard (DSR completion rate, audit pass rate, incident MTTR)
  • Role: viewer

GET /outcomes/comparative
  Query params: baseline_period, current_period
  • Compare metrics between periods
  • Role: viewer
```

### Project Documentation Portal (6 routes, WI-16)

```
GET /docs/brd
  • Read-only BRD (PRD-19)
  • Role: viewer

GET /docs/architecture
  • Read-only architecture documentation
  • Role: viewer

GET /docs/test-coverage
  • Test coverage summary and results
  • Role: viewer

GET /docs/cost-summary
  • Cost analysis and projections
  • Role: viewer

GET /docs/changelog
  • Version history and release notes
  • Role: viewer

GET /docs/glossary
  • Terminology and definitions
  • Role: viewer
```

### PDF Export Service (routes registered on all portals)

```
GET /export/audit/<audit_event_id>/pdf
  Query params: watermark (true|false), include_signatures (true|false)
  • Export audit event to PDF
  • Role: officer, auditor

GET /export/evidence/<evidence_id>/pdf
  Query params: watermark (true|false)
  • Export evidence to PDF (watermarked if auditor)
  • Role: officer, auditor

GET /export/report/<report_id>/pdf
  Query params: include_bundle (true|false)
  • Download signed report (PDF or ZIP with JWKS bundle, AMD-04)
  • Role: officer

POST /export/custom
  Body: {html_template: string, format: "pdf"|"png", safe_url_fetcher: bool}
  • Custom PDF/image export (SSRF-safe rendering, AMD-02)
  • Role: officer
```

---

## Public DSR Portal (8 routes)

### Data Subject Self-Service

```
GET /dsr/submit
  • Render DSR submission form
  • No auth required
  • CAPTCHA required

POST /dsr/submit
  Body: {request_type: "access"|"erasure"|"portability"|"rectification"|"automated_decision_review"|"objection", 
          email: string, name: string, dob: string, request_reason: string}
  • Submit Data Subject Request (GDPR Art 12, 15-22)
  • Rate limited (100 req/min, AMD-11)
  • No auth required

GET /dsr/status/<request_id>
  Query params: verification_token
  • Check DSR status (identity_pending → processing → completed)
  • Public endpoint (no auth, uses verification token)

POST /dsr/status/<request_id>/identity/upload
  Body: {document_image: base64_bytes}
  • Upload government ID for identity verification (AMD-01)
  • Scanned for malware
  • Stored securely
  • Public endpoint (no auth, uses request_id)

GET /dsr/evidence/<request_id>/download
  Query params: verification_token
  • Download evidence package (filtered for this data subject)
  • Watermarked with request_id + download timestamp
  • Public endpoint

POST /dsr/evidence/<request_id>/download/verify
  Body: {hash: string, hash_algorithm: "sha256"}
  • Verify evidence package integrity
  • Public endpoint

GET /dsr/faq
  • FAQ for Data Subjects (GDPR rights explained)
  • No auth required

GET /dsr/contact
  • Contact information for DPA/privacy team
  • No auth required
```

---

## Common HTTP Response Codes

```
200 OK         — Request succeeded
201 Created    — Resource created
204 No Content — Request succeeded (no body)
400 Bad Request       — Invalid input
401 Unauthorized      — Missing or invalid session
403 Forbidden         — Insufficient permissions or SoD violation
404 Not Found         — Resource not found
409 Conflict          — MFA nonce consumed or invalid state transition
429 Too Many Requests — Rate limit exceeded
500 Internal Error    — Server error
503 Unavailable       — Service temporarily unavailable
```

## Authentication Headers

```
Cookie: cp_session=<session_id>  # Set by /auth/callback
X-Decision-Nonce: <nonce>        # For MFA-bound decisions (AMD-03)
Authorization: Bearer <token>    # For auditor token-based access
```

## Rate Limiting Headers

```
X-RateLimit-Limit: 100           # Requests per minute
X-RateLimit-Remaining: 95        # Requests remaining
X-RateLimit-Reset: 1234567890    # Unix timestamp of reset
```

See **[ARCHITECTURE.md](./ARCHITECTURE.md)** for data flow diagrams and authentication flow details.
