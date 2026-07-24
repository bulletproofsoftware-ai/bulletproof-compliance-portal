# Compliance Portal

A FastAPI-based compliance and governance portal for managing DSR (Data Subject Request) workflows, audit trails, evidence packages, gate decisions, incident management, and regulatory reporting. Designed for compliance officers, external auditors, data subjects, and domain experts with role-based access control and comprehensive audit logging.

**Project**: PRD-19 | **Status**: Production-Ready (505 tests passing, 26 CISO amendments applied)

## What This Does

The Compliance Portal provides three distinct interfaces for three distinct user populations:

1. **Internal Portal** (`localhost:8443`): Compliance officer workspace for DSR triage, evidence review, gate decisions, incident management, model card governance, regulatory reporting, and auditor access provisioning.

2. **Public DSR Portal** (`localhost:8444`): Self-service intake for data subjects (GDPR Articles 15–22): access requests, erasure, portability, rectification, automated decision review. No Anthropic account required.

3. **Auditor Access**: Time-limited, scoped download of evidence packages, audit chains, gate records, and model cards with cryptographic integrity verification.

It surfaces the compliance service (PRD-18) to humans who aren't operators. Compliance officers can approve gate decisions with evidence review, triage DSRs within GDPR's 30-day window, manage security incidents against NY DFS's 72-hour notification clock, and sign off on annual model reviews.

## Features

- **DSR Management**: Submission, identity verification (AMD-01), status tracking, and evidence delivery per GDPR Articles 15–22
- **Gate Decision Workspace**: Evidence review, stakeholder notification, MFA step-up per decision (AMD-03), SoD enforcement
- **Audit Explorer**: Search, filter, and download audit trails with integrity verification (AMD-07)
- **Evidence Package Library**: Watermarked PDF delivery (AMD-08) with auditor identity embedded (AMD-06)
- **Auditor Access Controls**: Time-limited tokens, scope enforcement, separate admin portal
- **Incident Console**: SLA tracking (NY DFS 72-hour), audit emission, remediation workflows
- **Model Card Registry**: Annual sign-off tracking, domain expert review queues
- **Regulatory Report Generation**: Ed25519-signed delivery bundles (AMD-04) with JWKS anchors
- **Compliance Dashboards**: SLA compliance, remediation progress, risk heatmaps
- **Process Knowledge Verification**: Domain expert review queue for extracted knowledge
- **PDF Export Service**: Safe URL rendering (AMD-02), watermarking, cryptographic signatures
- **Project Documentation Portal**: Read-only BRD/architecture/test coverage/cost reporting
- **Security Hardening**: CORS, CSP, HSTS, rate limiting, audit guards (REQ-CPL-039), behavioral hooks

## Quick Start

### Prerequisites

- Python 3.12+
- Docker (optional, for Redis/PostgreSQL)
- `weasyprint` system dependencies: `brew install cairo pango gdk-pixbuf libffi` (macOS)

### Local Development (Internal Portal)

```bash
# Clone and setup
git clone <repo>
cd compliance-portal
make install          # creates .venv, installs deps

# Configure environment
cp .env.example .env
# Edit .env with your local values (see CONFIG.md for all vars)

# Run tests
make test             # 505 tests

# Start development server
make run              # http://localhost:8080 (plaintext, reload enabled)
```

Then navigate to `https://localhost:8443` in your browser (certificate verification not required for local dev).

### Local Development with Docker Compose

```bash
# Run internal + public portals, Redis, and PostgreSQL
docker compose -f docker-compose.dev.yml up

# Internal portal:  https://localhost:8443
# Public DSR:       https://localhost:8444
# Redis:            localhost:6379
# PostgreSQL:       localhost:5432 (user: portal, db: compliance_portal)
```

### Production Deployment

See **[INSTALLATION.md](./docs/INSTALLATION.md)** for:
- Server prerequisites and sizing
- Docker Compose production configuration
- Encryption-at-rest setup (AMD-09)
- Netbird configuration (internal portal isolation)
- WAF configuration (public portal rate limiting)
- mTLS bootstrap with compliance service
- Log aggregation and forwarding
- Initial admin account setup

## Architecture

The portal is split into two FastAPI applications:

```
src/portal/
├── main.py                          Internal portal (FastAPI factory)
├── public_app.py                    Public DSR portal (separate app)
├── config.py                        Pydantic settings, per-APP_MODE
├── logging.py                       Structlog with PII redaction (AMD-17)
│
├── auth/
│   ├── oidc.py                      OIDC + session management (AMD-15)
│   ├── rbac.py                      5 roles: admin, officer, auditor, sme, viewer
│   ├── mfa.py                       MFA step-up with nonce binding (AMD-03)
│   └── session.py                   Async session store (Redis or in-memory)
│
├── middleware/
│   ├── security.py                  CORS, CSP, HSTS, X-Forwarded-* parsing (WI-17)
│   ├── rate_limit.py                SlowAPI rate limiter (WI-17)
│   ├── audit.py                     Request/response audit logging (WI-17)
│   └── audit_guard.py               Runtime enforcement of REQ-CPL-039 (never write to immutable_audit_events)
│
├── routers/
│   ├── health.py                    Health checks and liveness
│   ├── audit.py                     GET /audit/* (search, download, integrity verify — WI-04)
│   ├── evidence.py                  GET /evidence/*/download with watermarking (WI-05)
│   ├── gates.py                     GET/POST /gates/* (workspace, decisions, MFA — WI-06)
│   ├── auditor_admin.py             POST /admin/auditors/* (token issuance, scope — WI-07)
│   ├── dsr.py                       Internal DSR routes: GET/POST /dsr/* (WI-08)
│   ├── export.py                    GET /export/* (PDF rendering, signing, SSRF-safe — WI-19)
│   ├── incidents.py                 GET/POST /incidents/* (SLA tracking, remediation — WI-10)
│   ├── model_cards.py               GET/POST /model-cards/* (sign-off, review queue — WI-11)
│   ├── reports.py                   GET/POST /reports/* (generate, sign, bundle — WI-12)
│   ├── dashboards.py                GET /dashboards/* (SLA, risk, remediation — WI-13)
│   ├── process_knowledge.py         GET/POST /knowledge/* (review queue, approve — WI-14)
│   ├── outcomes.py                  GET /outcomes/* (cost, timeline, success metrics — WI-15)
│   └── project_docs.py              GET /docs/* (read-only BRD, architecture, coverage — WI-16)
│
└── shared/
    └── api_client.py                Async httpx client to compliance service
                                    • Retry + circuit breaker
                                    • mTLS or bearer auth (AMD-10)
                                    • follow_redirects=False (AMD-25 SSRF defense)
```

### Two-Container Isolation

| Container | Mode | Port (Internal) | Port (Public) | Notes |
|-----------|------|-----------------|---------------|-------|
| Internal Portal | `APP_MODE=internal` | 8443 (TLS) | — | Compliance officers, auditors, SMEs |
| Public DSR Portal | `APP_MODE=public` | — | 8444 (TLS) | Data subjects, no auth required (CAPTCHA + rate limit) |

Both share: database, Redis session store, compliance service client, logging pipeline.

## Routes (Internal Portal)

**81 total routes across 14 routers**. See [API.md](./docs/API.md) for complete endpoint reference.

| Router | Routes | Purpose |
|--------|--------|---------|
| `health` | 2 | Liveness, readiness |
| `audit` | 8 | Search, filter, download audit trails; verify hashes (WI-04) |
| `evidence` | 6 | Download evidence packages, watermarked PDFs (WI-05) |
| `gates` | 12 | View pending decisions, submit decisions, MFA step-up (WI-06) |
| `auditor_admin` | 7 | Create/revoke auditor tokens, set scope (WI-07) |
| `dsr` | 9 | View submitted requests, assign to reviewer, update status (WI-08) |
| `incidents` | 6 | Create, assign, track SLA, record remediation (WI-10) |
| `model_cards` | 7 | View models, download cards, record sign-off (WI-11) |
| `reports` | 6 | Generate report, sign, download, verify bundle (WI-12) |
| `dashboards` | 5 | SLA compliance heatmap, risk dashboard, remediation pipeline (WI-13) |
| `process_knowledge` | 5 | List candidates, approve/reject/modify, record decision (WI-14) |
| `outcomes` | 4 | View cost, timeline, success metrics, KPI dashboards (WI-15) |
| `project_docs` | 6 | Read-only BRD, architecture, test coverage, cost summary (WI-16) |

Public DSR Portal: **8 routes** for submission, status tracking, identity verification, and evidence download.

## Development Commands

```bash
make help            # Show all targets
make lint            # Run ruff check + format
make type            # Run mypy type checking
make test            # Run pytest (all 505 tests)
make test-verbose    # pytest -v
make run             # Start dev server with reload
make docker-build    # Build internal + public images (WI-18)
make clean           # Remove venv, caches
```

## Testing

**505 tests** across functional, integration, and security domains:

```bash
make test                    # Run all (3.4s)
pytest tests/test_auth.py    # Auth + OIDC + MFA
pytest tests/test_dsr.py     # DSR workflows + identity verification
pytest tests/test_gates.py   # Gate decisions + SoD + MFA step-up
pytest tests/test_audit.py   # Audit explorer + hash verification
pytest tests/test_incidents.py   # Incident SLA tracking
pytest tests/test_pdf.py     # PDF rendering (SSRF safety, watermarking, signatures)
```

Test suite covers:
- **Functional**: All CRUD operations, state transitions, SLA tracking
- **Security**: OIDC callback validation, MFA nonce binding (AMD-03), PDF SSRF (AMD-02), audit immutability (REQ-CPL-039)
- **Integration**: Compliance service client, Redis session store, PostgreSQL views
- **Adversarial**: Role bypass attempts, SoD violations, privilege escalation

## Security

See **[SECURITY.md](./SECURITY.md)** for vulnerability disclosure policy and security contact.

**Key invariants** (26 CISO amendments applied 2026-04-27):

- **AMD-01**: Public DSR identity verification with document validation, name/DOB matching, expiration checking
- **AMD-02**: Safe URL rendering in PDF exports; SSRF blocking on non-`file://` schemes
- **AMD-03**: MFA step-up per decision with nonce binding (max 60s lifetime, consumed after use)
- **AMD-04**: Ed25519-signed regulatory reports with JWKS anchors and key rotation policy
- **AMD-10**: mTLS *or* IP allowlist (never bearer token alone) for portal→service hop
- **AMD-15**: Session ID rotation on OIDC callback (defeat session fixation)
- **AMD-17**: PII redaction (`subject_email`, `subject_name`, `subject_phone`, `subject_address`, `dob`) in logs at any nesting depth
- **AMD-25**: `httpx.AsyncClient` with `follow_redirects=False` (block SSRF amplification)
- **REQ-CPL-039**: Static + runtime guards: no code path writes to `immutable_audit_events`

## Documentation

- **[README.md](./README.md)** — This file
- **[ARCHITECTURE.md](./docs/ARCHITECTURE.md)** — Component design, data flows, trust boundaries, threat model
- **[SETUP.md](./docs/SETUP.md)** — Development setup, dependency installation, environment variables
- **[INSTALLATION.md](./docs/INSTALLATION.md)** — Production deployment, Docker Compose, TLS bootstrap, log forwarding
- **[API.md](./docs/API.md)** — All 81 internal + 8 public routes with method, path, role, description
- **[CONFIG.md](./docs/CONFIG.md)** — Environment variable reference, feature flags, per-environment values
- **[FAQ.md](./docs/FAQ.md)** — Top 15 questions (two containers, role differences, PDF watermarking, etc.)
- **[CONTRIBUTING.md](./docs/CONTRIBUTING.md)** — Development workflow, code standards, PR process
- **[CHANGELOG.md](./docs/CHANGELOG.md)** — Version history
- **[INCIDENT-RESPONSE.md](./docs/INCIDENT-RESPONSE.md)** — Security incident handling, SLA tracking, remediation
- **[CHANGE-MANAGEMENT.md](./docs/CHANGE-MANAGEMENT.md)** — Code review, deployment gates, rollback
- **[SUPPORT-POLICY.md](./docs/SUPPORT-POLICY.md)** — Support tiers, SLA, escalation
- **[SECURITY-EOL.md](./docs/SECURITY-EOL.md)** — Version support lifecycle

## License

Proprietary. All rights reserved.

## Contributing

See **[CONTRIBUTING.md](./docs/CONTRIBUTING.md)**.

## Project Specs

All 19 work items (WI-01 through WI-19) from PRD-19 are implemented:

| WI | Name | Status |
|----|------|--------|
| WI-01 | Project skeleton | Implemented |
| WI-02 | Auth & RBAC | Implemented |
| WI-03 | Compliance API client | Implemented |
| WI-04 | Audit Explorer | Implemented |
| WI-05 | Evidence Package Library | Implemented |
| WI-06 | Gate Decision Workspace | Implemented |
| WI-07 | Auditor Access Controls | Implemented |
| WI-08 | DSR Management | Implemented |
| WI-09 | Public DSR Portal | Implemented |
| WI-10 | Incident Console | Implemented |
| WI-11 | Model Card Registry | Implemented |
| WI-12 | Regulatory Report Generation | Implemented |
| WI-13 | Compliance Dashboards | Implemented |
| WI-14 | Process Knowledge Verification | Implemented |
| WI-15 | Outcome Economics Views | Implemented |
| WI-16 | Project Documentation Portal | Implemented |
| WI-17 | Security Hardening | Implemented |
| WI-18 | Docker Deployment | Implemented |
| WI-19 | PDF Export Service | Implemented |

See **[docs/completeness-report-2026-04-27.md](./docs/completeness-report-2026-04-27.md)** for detailed verification.
