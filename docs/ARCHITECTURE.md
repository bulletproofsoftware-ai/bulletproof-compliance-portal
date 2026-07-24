# Architecture Overview

## System Design

The Compliance Portal is a dual-mode FastAPI application providing separate interfaces for internal compliance workflows and public GDPR self-service intake. Both modes share a single database, Redis session store, message queue integration, and compliance service client.

### Component Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                           Browser / Client                            │
└──────────┬─────────────────────────────────────────────────────┬──────┘
           │                                                      │
    ┌──────▼──────────┐                                  ┌──────▼──────────┐
    │ Internal Portal │                                  │  Public Portal   │
    │ (port 8443)     │                                  │  (port 8444)     │
    │                 │                                  │                  │
    │ • OIDC auth     │                                  │ • CAPTCHA +      │
    │ • 5 roles       │                                  │   rate limit     │
    │ • 81 routes     │                                  │ • 8 routes       │
    │ • TLS required  │                                  │ • No auth        │
    └────────┬────────┘                                  └────────┬────────┘
             │                                                    │
             └────────────────────┬─────────────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │    Shared Services         │
                    ├───────────────────────────┤
                    │ • FastAPI app factory     │
                    │ • Settings (pydantic)     │
                    │ • Logging (structlog)     │
                    │ • Auth (OIDC + RBAC)      │
                    │ • Middleware (security)   │
                    │ • Database (PostgreSQL)   │
                    │ • Session store (Redis)   │
                    │ • Knowledge index (Qdrant)│
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │  Compliance Service       │
                    │  (PRD-18 enforcement)     │
                    ├───────────────────────────┤
                    │ • 10 REST endpoints       │
                    │ • mTLS or IP allowlist    │
                    │ • Circuit breaker         │
                    │ • Async httpx client      │
                    └───────────────────────────┘
```

## Router Architecture (Internal Portal)

The internal portal registers 14 routers at startup, each responsible for a distinct business domain:

```
main.py (APP_MODE=internal)
│
├── health.router                      Health checks
├── auth.build_auth_router()           OIDC callback, session mgmt, logout
├── export.router                      PDF rendering, signing, watermarking (WI-19)
├── audit.router                       Audit explorer, download, verify (WI-04)
├── evidence.router                    Evidence packages, watermarked PDF (WI-05)
├── gates.router                       Gate decisions, MFA step-up, SoD (WI-06)
├── auditor_admin.router               Token issuance, scope control (WI-07)
├── dsr.router                         Internal DSR workflows (WI-08)
├── incidents.router                   Incident management, SLA tracking (WI-10)
├── incidents.webhook_router           Compliance service incident webhooks
├── model_cards.router                 Model card registry, sign-off (WI-11)
├── reports.router                     Report generation, signing (WI-12)
├── dashboards.router                  Compliance heatmaps, risk views (WI-13)
├── process_knowledge.router           Expert review queue (WI-14)
├── outcomes.router                    Cost, timeline, KPI metrics (WI-15)
└── project_docs.router                Read-only documentation portal (WI-16)
```

The public portal (`APP_MODE=public`) registers only a subset:
- `health.router`
- `export.router` (PDF download for evidence)
- Public DSR routers (submission, status, evidence download)

## Data Flow Diagrams

### Gate Decision Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Compliance Officer views pending gate decision               │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   │ GET /gates/<id>
                   │
        ┌──────────▼─────────────────────┐
        │ gates.py → get_decision()       │
        │ • Fetch from compliance service │
        │ • Load linked evidence          │
        │ • Render template               │
        └──────────┬──────────────────────┘
                   │
        ┌──────────▼──────────────────────┐
        │ Render gate detail page         │
        │ • Evidence thumbnails           │
        │ • Decision options              │
        │ • MFA step-up required (AMD-03) │
        │ • Issue decision_nonce          │
        └──────────┬──────────────────────┘
                   │
                   │ User selects decision option, clicks MFA
                   │
        ┌──────────▼─────────────────────────┐
        │ MFA Challenge                      │
        │ • /auth/mfa/challenge              │
        │ • Nonce bound to (user_sub, gate_id) │
        │ • Max age 60s (AMD-03)              │
        └──────────┬──────────────────────────┘
                   │
                   │ User completes MFA (TOTP/WebAuthn)
                   │
        ┌──────────▼──────────────────────────┐
        │ POST /auth/mfa/verify               │
        │ • Validate nonce & binding          │
        │ • Consume nonce (reject replay)     │
        │ • Issue session with mfa_verified   │
        └──────────┬──────────────────────────┘
                   │
                   │ User submits decision
                   │
        ┌──────────▼──────────────────────────┐
        │ POST /gates/<id>/decide             │
        │ • Verify session has mfa_verified   │
        │ • Check SoD: submitter ≠ original   │
        │   requester                         │
        │ • Validate decision within options  │
        └──────────┬──────────────────────────┘
                   │
        ┌──────────▼──────────────────────────┐
        │ gates.py → submit_decision()        │
        │ • POST /compliance/gates/<id>/      │
        │   decide (mTLS, AMD-10)             │
        │ • Include MFA proof                 │
        │ • Include decision evidence link    │
        └──────────┬──────────────────────────┘
                   │
        ┌──────────▼──────────────────────────┐
        │ Compliance service                  │
        │ • Store decision                    │
        │ • Emit audit event                  │
        │ • Update gate state                 │
        │ • Trigger downstream (notify, etc)  │
        └──────────┬──────────────────────────┘
                   │
        ┌──────────▼──────────────────────────┐
        │ Audit log                           │
        │ gate.decision_submitted             │
        │ • gate_id, officer_sub              │
        │ • decision, evidence_links          │
        │ • mfa_verified_at                   │
        │ • Immutable (REQ-CPL-039)           │
        └──────────────────────────────────────┘
```

### DSR Submission + Identity Verification Flow (AMD-01)

```
┌─────────────────────────────────────┐
│ Data subject at public portal        │
└──────────────┬──────────────────────┘
               │
               │ POST /dsr/submit
               │ • Type (access, erasure, portability, etc)
               │ • Email, name, DOB
               │ • Request reason (optional)
               │
    ┌──────────▼─────────────────────┐
    │ public_app.py                   │
    │ • CAPTCHA verification          │
    │ • Rate limit check              │
    │ • Basic data validation         │
    └──────────┬──────────────────────┘
               │
    ┌──────────▼──────────────────────────────┐
    │ POST /compliance/dsr/submit             │
    │ • Service-account token (AMD-05 ACL)    │
    │ • Creates DSR with state = "received"   │
    │ • Returns dsr_id                        │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────▼────────────────────────────────┐
    │ Redirect to status page                   │
    │ dsr_state = "identity_pending"            │
    │ Prompt for identity document upload       │
    └──────────┬────────────────────────────────┘
               │
               │ User uploads government ID image
               │
    ┌──────────▼──────────────────────────────┐
    │ POST /dsr/<id>/identity/upload          │
    │ • Scan for malware                       │
    │ • Store securely                         │
    │ • Emit dsr.identity_proof.uploaded       │
    │ • Request → "identity_verification"     │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────┐
    │ Internal Portal                          │
    │ /dsr/reviews (auditor dashboard)         │
    │ • Lists pending identity verifications   │
    │ • Sorts by sensitivity (erasure first)   │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────┐
    │ Auditor clicks review                    │
    │ GET /dsr/<id>/identity/review           │
    │ • Display: uploaded image, document box  │
    │ • Name field, DOB field, expiry date    │
    │ • Extract checkbox, Reject checkbox      │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────▼──────────────────────────────┐
    │ Auditor decision                         │
    │ POST /dsr/<id>/identity/verify           │
    │ • decision: "approved" | "rejected"      │
    │ • For high-sensitivity (erasure): must   │
    │   have supervisor sign-off (SoD)         │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────┴──────────────────────────────┐
    │                                          │
    │ (approved)                 (rejected)    │
    │                                          │
┌───▼──────────────────┐    ┌──────────────────▼──┐
│ dsr_state =          │    │ dsr_state =         │
│ "processing"         │    │ "identity_rejected" │
│                      │    │                     │
│ Emit audit:          │    │ Notify subject:     │
│ dsr.identity_        │    │ identity not        │
│ verified             │    │ verified; appeal    │
│                      │    │ process available   │
└──────────────────────┘    └─────────────────────┘
```

### Evidence Download + Watermarking Flow

```
┌─────────────────────────────────────────┐
│ Auditor with limited token requests     │
│ evidence package download                │
└──────────────┬──────────────────────────┘
               │
               │ GET /evidence/<evidence_id>/download
               │ Header: Authorization: Bearer <auditor_token>
               │
    ┌──────────▼──────────────────────────┐
    │ evidence.py → get_evidence()         │
    │ • Validate token is non-expired      │
    │ • Check token scope includes this ID │
    │ • Fetch from compliance service      │
    │ • Extract PDF bytes                  │
    └──────────┬──────────────────────────┘
               │
    ┌──────────▼──────────────────────────┐
    │ PDF watermarking (AMD-08)            │
    │ • Add: "[CONFIDENTIAL - AUDITOR]"    │
    │ • Add: token issue date + expiry     │
    │ • Add: auditor name (from token)     │
    │ • Embed metadata (AMD-06):           │
    │   - /X-Compliance-Auditor-Sub        │
    │   - /X-Compliance-Engagement-Id      │
    │   - /X-Compliance-Exported-At        │
    │   - /X-Compliance-Watermark-Id       │
    └──────────┬──────────────────────────┘
               │
    ┌──────────▼──────────────────────────┐
    │ export.py → apply_watermark()        │
    │ • Use pikepdf to add watermark layer │
    │ • Uses safe_url_fetcher (AMD-02)     │
    │ • No external URL fetch              │
    └──────────┬──────────────────────────┘
               │
    ┌──────────▼──────────────────────────┐
    │ Return response                      │
    │ Content-Type: application/pdf        │
    │ Content-Disposition:                 │
    │   attachment;                        │
    │   filename=evidence_<id>_watermarked │
    └──────────────────────────────────────┘
```

### PDF Export with Cryptographic Signing

```
┌──────────────────────────────────────┐
│ Compliance officer generates report  │
│ for regulatory delivery              │
└──────────┬───────────────────────────┘
           │
           │ GET /reports/<id>/preview
           │
    ┌──────▼──────────────────────────┐
    │ reports.py → get_report()        │
    │ • Fetch report data              │
    │ • Load template (Jinja2)         │
    │ • Render to HTML                 │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────────────────────────┐
    │ Officer reviews, clicks "Export" │
    │ POST /reports/<id>/export        │
    │ • Require MFA step-up (AMD-03)   │
    │ • signing_key_id from settings   │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────────────────────────┐
    │ export.py → render_to_pdf()      │
    │ • Parse HTML + CSS (Jinja2)      │
    │ • weasyprint.HTML(...)           │
    │ • safe_url_fetcher (AMD-02)      │
    │ • Returns PDF bytes              │
    └──────┬──────────────────────────┘
           │
    ┌──────▼─────────────────────────────┐
    │ Embed signature + metadata (AMD-04)│
    │ • Fetch JWKS from compliance srv   │
    │ • Get current signing key          │
    │ • Compute Ed25519 signature of PDF │
    │ • Embed in /Signature dict         │
    │ • Embed /Metadata (AMD-06):        │
    │   - signing_key_id                 │
    │   - signed_at (ISO8601)            │
    │   - report_id                      │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────────────────────────┐
    │ Create delivery bundle           │
    │ • report-<id>.pdf (signed)       │
    │ • jwks.json (snapshot)           │
    │ • signatures.json                │
    │ • metadata.json                  │
    └──────┬──────────────────────────┘
           │
    ┌──────▼──────────────────────────┐
    │ Return ZIP download              │
    │ Content-Type: application/zip    │
    │ Include checksum manifest        │
    └──────────────────────────────────┘
```

## Authentication Flow

```
┌──────────────────────────────────────┐
│ User navigates to /dashboard         │
└──────────────┬──────────────────────┘
               │
    ┌──────────▼──────────────────────┐
    │ No session cookie               │
    │ Redirect to /auth/oidc           │
    └──────────┬──────────────────────┘
               │
    ┌──────────▼──────────────────────┐
    │ auth.py → oidc_login()           │
    │ • Generate code_verifier (PKCE)  │
    │ • Generate nonce                 │
    │ • Redirect to OIDC issuer        │
    │   /authorize?                    │
    │     client_id=...&               │
    │     redirect_uri=...&            │
    │     code_challenge=...&          │
    │     nonce=...&                   │
    │     scope=openid profile email   │
    └──────────┬──────────────────────┘
               │
    ┌──────────▼──────────────────────────────┐
    │ OIDC Provider                            │
    │ • User authenticates (password, WebAuthn)│
    │ • Optional MFA (if configured)          │
    │ • Redirects back to /auth/callback?     │
    │   code=...&state=...                    │
    └──────────┬──────────────────────────────┘
               │
    ┌──────────▼──────────────────────┐
    │ auth.py → oidc_callback()        │
    │ • Verify state                   │
    │ • POST /token with code_verifier │
    │ • Verify nonce in ID token       │
    │ • Extract subject (sub)          │
    │ • Resolve groups → roles (AMD-05)│
    │ • Rotate session ID (AMD-15)     │
    │ • Set secure cookie              │
    └──────────┬──────────────────────┘
               │
    ┌──────────▼──────────────────────┐
    │ Redirect to original destination │
    │ (/dashboard)                     │
    └──────────────────────────────────┘
```

## Role-Based Access Control (RBAC)

```
Role          Permissions                          Use Case
────────────────────────────────────────────────────────────────────
admin         • All routes                         System administrator
              • User/token mgmt
              • Audit log access
              • Config changes

officer       • View/update DSR status             Compliance officer
              • Submit gate decisions
              • Review evidence
              • Manage incidents
              • View dashboards
              • Generate reports

auditor       • View-only access                   External auditor
              • Limited by engagement token
              • Download evidence
              • Verify signatures
              • Download audit trails
              • No write permissions

sme           • Review process knowledge queue     Subject matter expert
              • Approve/reject/modify candidates
              • Document decision
              • No DSR/gate/incident access

viewer        • Read-only access                   Stakeholder
              • View documentation
              • View outcomes/cost/timeline
              • No sensitive data access
```

## Network Topology

```
┌──────────────────────────────────────────────────────────┐
│                      Internet                            │
└──────┬──────────────────────────────────────────┬────────┘
       │                                          │
   [WAF]                                      [WAF]
       │                                          │
       │ TLS 1.3                                  │ TLS 1.3
       │                                          │
┌──────▼────────┐                         ┌──────▼─────────┐
│ :8443         │                         │ :8444          │
│ Internal      │                         │ Public DSR      │
│ Portal        │                         │ Portal          │
│               │                         │                │
│ • OIDC        │                         │ • CAPTCHA       │
│   required    │                         │ • Rate limit    │
│ • Roles       │                         │ • No auth       │
│ • 5 roles     │                         │                │
└──────┬────────┘                         └──────┬─────────┘
       │                                         │
       └─────────────────┬──────────────────────┘
                         │
        ┌────────────────▼────────────────┐
        │ Shared Services (localhost)     │
        ├─────────────────────────────────┤
        │ PostgreSQL :5432                │
        │ • read_only user                │
        │ • compliance_portal database    │
        │                                 │
        │ Redis :6379                     │
        │ • Session store (hashed IDs)    │
        │ • Rate limit counters           │
        │                                 │
        │ Qdrant :6333                    │
        │ • Process knowledge index       │
        │                                 │
        │ FastAPI (shared config/auth)    │
        └────────────────┬────────────────┘
                         │
        ┌────────────────▼──────────────────────┐
        │ Compliance Service (PRD-18)           │
        │ https://compliance-svc.internal/api/v1│
        │                                       │
        │ mTLS Cert (AMD-10)                    │
        │ + Client IP allowlist                 │
        │ + Circuit breaker                     │
        │ + Retry with exponential backoff      │
        └───────────────────────────────────────┘
```

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 1: External → Portal                             │
├─────────────────────────────────────────────────────────────────┤
│ • HTTPS/TLS mandatory                                           │
│ • OIDC token validation (internal)                              │
│ • CAPTCHA (public portal)                                       │
│ • Rate limiting (all)                                           │
│ • CSRF token validation (form submissions)                      │
│ • CSP header enforcement                                        │
│ • X-Forwarded-* parsing (only from TRUSTED_PROXIES)           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 2: Portal → Database                             │
├─────────────────────────────────────────────────────────────────┤
│ • Dedicated read-only user account                              │
│ • Parameterized queries (no SQL injection)                      │
│ • Connection pooling (async)                                    │
│ • Audit log writes via compliance service (indirect)            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 3: Portal → Compliance Service                   │
├─────────────────────────────────────────────────────────────────┤
│ • mTLS OR IP allowlist (AMD-10, never bearer alone)            │
│ • Service-account token for public portal (AMD-05)              │
│ • Circuit breaker (fail closed on service unavail)              │
│ • Timeout enforcement (max 10s)                                 │
│ • No redirect following (AMD-25 SSRF defense)                   │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 4: Audit Log (Immutable)                         │
├─────────────────────────────────────────────────────────────────┤
│ • REQ-CPL-039: Static + runtime guards                          │
│ • No portal code writes directly to audit_events               │
│ • All audit via compliance service (single source of truth)     │
│ • Audit guard middleware blocks direct writes                   │
└─────────────────────────────────────────────────────────────────┘
```

## Security Architecture

### OIDC + MFA + Session Management

1. **Initial Login**: OIDC authorization code flow (PKCE)
2. **Token Exchange**: Code → ID token (nonce verified)
3. **Session Creation**: Rotate session ID post-callback (AMD-15 session fixation defense)
4. **Group → Role Mapping**: Extract groups from ID token, map to RBAC roles
5. **MFA Step-Up**: Per sensitive operation (gate decision, report signing, model card sign-off)
   - Nonce issued on page render
   - Bound to (user_sub, resource_id)
   - Consumed after verification (replay protection)
   - Max lifetime 60s (AMD-03)

### PII Redaction in Logs (AMD-17)

All logging routes through `structlog` with custom redactor. Pattern-matched fields redacted at any nesting depth:
- `subject_email` → `[REDACTED-EMAIL]`
- `subject_name` → `[REDACTED-NAME]`
- `subject_phone` → `[REDACTED-PHONE]`
- `subject_address` → `[REDACTED-ADDRESS]`
- `dob` → `[REDACTED-DOB]`

### PDF SSRF Protection (AMD-02)

Safe URL fetcher in `export.py`:

```python
def safe_url_fetcher(url):
    parsed = urllib.parse.urlparse(url)
    # Only allow file:// scheme
    if parsed.scheme != 'file':
        raise ValueError(f'Disallowed scheme: {parsed.scheme}')
    
    # Block paths outside static directory
    path = urllib.parse.unquote(parsed.path)
    if not path.startswith(STATIC_ROOT):
        raise ValueError(f'Path outside STATIC_ROOT: {path}')
    
    return open(path, 'rb').read()
```

Wired into every `weasyprint.HTML(...)` call. Jinja2 autoescaping enforced. Ban on `|safe` in template fields flowing into `src=` / `href=` / `url(...)`.

### Audit Immutability Enforcement (REQ-CPL-039)

Two-layer enforcement:
1. **Static check in CI**: `ruff` rule bans `audit_events.insert()` / `audit_events.update()` in portal code
2. **Runtime guard**: Middleware checks request target; if it's `/audit_events/*` write, block with 403

### Ed25519 Signing + JWKS (AMD-04)

Regulatory report exports signed with Ed25519:
- Key rotation policy: Annual + on-compromise
- 90-day overlap window (old key valid while new key propagates)
- JWKS endpoint: `GET /api/v1/compliance/keys/jwks.json` (no auth)
- Public key ID in report metadata
- Verification example provided in docs

## Threat Model Summary

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|-----------|
| Session fixation | High | High | AMD-15 ID rotation on OIDC callback |
| DSR identity spoofing | Medium | Critical | AMD-01 document validation + metadata check |
| Unauthorized evidence download | Medium | High | Token scope enforcement + time limits |
| PDF render-time SSRF | Medium | Critical | AMD-02 safe URL fetcher + URL scheme whitelist |
| MFA replay | Low | High | AMD-03 nonce binding + consumption |
| Unauthorized gate decision | Medium | High | SoD (submitter ≠ requester) + MFA |
| Audit log tampering | Low | Critical | REQ-CPL-039 immutability guards + encryption at rest |
| Portal→service privilege escalation | Low | High | AMD-10 mTLS (never bearer alone) + AMD-05 ACL |
| PII in logs | Medium | High | AMD-17 structured redaction at all nesting levels |

See **[CISO-architecture-review.md](./CISO-architecture-review.md)** for detailed security assessment.
