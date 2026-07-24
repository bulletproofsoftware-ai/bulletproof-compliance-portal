# Compliance Portal

A FastAPI-based compliance and governance portal for managing DSR (Data Subject Request) workflows, audit trails, evidence packages, gate decisions, incident management, and regulatory reporting. Designed for compliance officers, external auditors, data subjects, and domain experts with role-based access control and comprehensive audit logging.

> 📚 Full documentation in [`docs/`](docs/) · 🔒 security scan in [`docs/scan/scan-report.md`](docs/scan/scan-report.md). (System-overview media coming soon.)

## What This Does

The Compliance Portal provides three distinct interfaces for three distinct user populations:

1. **Internal Portal** (`localhost:8443`): Compliance officer workspace for DSR triage, evidence review, gate decisions, incident management, model card governance, regulatory reporting, and auditor access provisioning.

2. **Public DSR Portal** (`localhost:8444`): Self-service intake for data subjects (GDPR Articles 15–22): access requests, erasure, portability, rectification, automated decision review. No Anthropic account required.

3. **Auditor Access**: Time-limited, scoped download of evidence packages, audit chains, gate records, and model cards with cryptographic integrity verification.

It surfaces the compliance service to humans who aren't operators. Compliance officers can approve gate decisions with evidence review, triage DSRs within GDPR's 30-day window, manage security incidents against NY DFS's 72-hour notification clock, and sign off on annual model reviews.

## Features

- **DSR Management**: Submission, identity verification, status tracking, and evidence delivery per GDPR Articles 15–22
- **Gate Decision Workspace**: Evidence review, stakeholder notification, MFA step-up per decision, SoD enforcement
- **Audit Explorer**: Search, filter, and download audit trails with integrity verification
- **Evidence Package Library**: Watermarked PDF delivery with auditor identity embedded
- **Auditor Access Controls**: Time-limited tokens, scope enforcement, separate admin portal
- **Incident Console**: SLA tracking (NY DFS 72-hour), audit emission, remediation workflows
- **Model Card Registry**: Annual sign-off tracking, domain expert review queues
- **Regulatory Report Generation**: Ed25519-signed delivery bundles with JWKS anchors
- **Compliance Dashboards**: SLA compliance, remediation progress, risk heatmaps
- **Process Knowledge Verification**: Domain expert review queue for extracted knowledge
- **PDF Export Service**: Safe URL rendering, watermarking, cryptographic signatures
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
make test             # 556 tests

# Start development server
make run              # http://localhost:8080 (plaintext, reload enabled)
```

Then navigate to `http://localhost:8080` in your browser.

### Local Development with Docker Compose

Both nginx front-ends terminate TLS, so generate certificates first. They are
bind-mounted from `docker/nginx/certs/`, which is gitignored — the filenames
below are the ones `docker/nginx/internal.conf` and `docker/nginx/public.conf`
reference, so use them exactly:

```bash
mkdir -p docker/nginx/certs && cd docker/nginx/certs
for name in internal public; do
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${name}.key" -out "${name}.crt" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
done
chmod 600 ./*.key && cd ../../..
```

The `compliance_service` container builds from a sibling clone; see the comment
above that service in `docker/compose.yaml` if you have not cloned it yet.

```bash
# Run internal + public portals, Redis, and PostgreSQL
docker compose -f docker/compose.yaml up

# Internal portal:  https://localhost:8443
# Public DSR:       https://localhost:8444
# Redis:            localhost:6379
# PostgreSQL:       localhost:5432 (user: portal, db: compliance_portal)
```

Browsers will warn about the self-signed chain; that is expected locally. For
production certificates see [INSTALLATION.md](./docs/INSTALLATION.md).

### Production Deployment

See **[INSTALLATION.md](./docs/INSTALLATION.md)** for:
- Server prerequisites and sizing
- Docker Compose production configuration
- Encryption-at-rest setup
- Private overlay network setup (internal portal isolation)
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
├── logging.py                       Structlog with PII redaction
│
├── auth/
│   ├── oidc.py                      OIDC + session management
│   ├── rbac.py                      5 roles: admin, officer, auditor, sme, viewer
│   ├── mfa.py                       MFA step-up with nonce binding
│   └── session.py                   Async session store (Redis or in-memory)
│
├── middleware/
│   ├── security_headers.py          CORS, CSP, HSTS, X-Forwarded-* parsing
│   ├── rate_limit.py                SlowAPI rate limiter
│   ├── audit.py                     Request/response audit logging
│   └── audit_guard.py               Runtime enforcement of REQ-CPL-039 (never write to immutable_audit_events)
│
└── routers/
    ├── health.py                    Health checks and liveness
    ├── audit.py                     GET /audit/* (search, download, integrity verify)
    ├── evidence.py                  GET /evidence/*/download with watermarking
    ├── gates.py                     GET/POST /gates/* (workspace, decisions, MFA)
    ├── auditor_admin.py             POST /admin/auditors/* (token issuance, scope)
    ├── dsr.py                       Internal DSR routes: GET/POST /dsr/*
    ├── export.py                    GET /export/* (PDF rendering, signing, SSRF-safe)
    ├── incidents.py                 GET/POST /incidents/* (SLA tracking, remediation)
    ├── model_cards.py               GET/POST /model-cards/* (sign-off, review queue)
    ├── reports.py                   GET/POST /reports/* (generate, sign, bundle)
    ├── dashboards.py                GET /dashboards/* (SLA, risk, remediation)
    ├── process_knowledge.py         GET/POST /knowledge/* (review queue, approve)
    ├── outcomes.py                  GET /outcomes/* (cost, timeline, success metrics)
    └── project_docs.py              GET /docs/* (read-only BRD, architecture, coverage)

src/dsr_portal/                      Public DSR portal (APP_MODE=public)
├── main.py                          Public app factory
├── captcha.py                       CAPTCHA verification for anonymous submission
├── identity_state_machine.py        Identity-verification state transitions
├── malware_scan.py                  Upload scanning for submitted proof documents
├── auth/
│   └── token.py                     Opaque status-tracking tokens
└── routers/
    └── submit.py                    POST /submit, status lookup, evidence download

src/shared/
└── api_client/                      Async httpx client to compliance service
                                     • Retry + circuit breaker
                                     • mTLS or bearer auth
                                     • follow_redirects=False (SSRF defense)
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
| `audit` | 8 | Search, filter, download audit trails; verify hashes |
| `evidence` | 6 | Download evidence packages, watermarked PDFs |
| `gates` | 12 | View pending decisions, submit decisions, MFA step-up |
| `auditor_admin` | 7 | Create/revoke auditor tokens, set scope |
| `dsr` | 9 | View submitted requests, assign to reviewer, update status |
| `incidents` | 6 | Create, assign, track SLA, record remediation |
| `model_cards` | 7 | View models, download cards, record sign-off |
| `reports` | 6 | Generate report, sign, download, verify bundle |
| `dashboards` | 5 | SLA compliance heatmap, risk dashboard, remediation pipeline |
| `process_knowledge` | 5 | List candidates, approve/reject/modify, record decision |
| `outcomes` | 4 | View cost, timeline, success metrics, KPI dashboards |
| `project_docs` | 6 | Read-only BRD, architecture, test coverage, cost summary |

Public DSR Portal: **8 routes** for submission, status tracking, identity verification, and evidence download.

## Development Commands

```bash
make help            # Show all targets
make lint            # Run ruff check + format
make type            # Run mypy type checking
make test            # Run pytest (all 556 tests)
make test-verbose    # pytest -v
make run             # Start dev server with reload
make docker-build    # Not implemented — prints a pointer. Use:
                     #   docker compose -f docker/compose.yaml build
make clean           # Remove venv, caches
```

## Testing

**556 tests** across functional, integration, and security domains:

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
- **Security**: OIDC callback validation, MFA nonce binding, PDF SSRF, audit immutability (REQ-CPL-039)
- **Integration**: Compliance service client, Redis session store, PostgreSQL views
- **Adversarial**: Role bypass attempts, SoD violations, privilege escalation

## Security

See **[SECURITY.md](./SECURITY.md)** for vulnerability disclosure policy and security contact.

**Key security controls**:

- Public DSR identity verification with document validation, name/DOB matching, expiration checking
- Safe URL rendering in PDF exports; SSRF blocking on non-`file://` schemes
- MFA step-up per decision with nonce binding (max 60s lifetime, consumed after use)
- Ed25519-signed regulatory reports with JWKS anchors and key rotation policy
- mTLS *or* IP allowlist (never bearer token alone) for portal→service hop
- Session ID rotation on OIDC callback (defeat session fixation)
- PII redaction (`subject_email`, `subject_name`, `subject_phone`, `subject_address`, `dob`) in logs at any nesting depth
- `httpx.AsyncClient` with `follow_redirects=False` (block SSRF amplification)
- **REQ-CPL-039**: Static + runtime guards: no code path writes to `immutable_audit_events`

## Documentation

- **[README.md](./README.md)** — This file
- **[OVERVIEW.md](./docs/OVERVIEW.md)** — What the portal is, the three surfaces, capabilities, and route map
- **[INSTALL.md](./docs/INSTALL.md)** — Quick install & run (local + Docker Compose)
- **[HOW-TO-USE.md](./docs/HOW-TO-USE.md)** — Task-oriented walkthroughs by role
- **[ADMINISTRATOR.md](./docs/ADMINISTRATOR.md)** — Day-2 operations: auth, secrets, isolation, provisioning
- **[SBOM.md](./docs/SBOM.md)** — Software bill of materials (real, generated from manifests)
- **[scan/scan-report.md](./docs/scan/scan-report.md)** — Latest security scan (0 critical / 0 high)
- **[ARCHITECTURE.md](./docs/ARCHITECTURE.md)** — Component design, data flows, trust boundaries, threat model
- **[SETUP.md](./docs/SETUP.md)** — Development setup, dependency installation, environment variables
- **[INSTALLATION.md](./docs/INSTALLATION.md)** — Production deployment, Docker Compose, TLS bootstrap, log forwarding
- **[API.md](./docs/API.md)** — All 81 internal + 8 public routes with method, path, role, description
- **[CONFIG.md](./docs/CONFIG.md)** — Environment variable reference, feature flags, per-environment values
- **[FAQ.md](./docs/FAQ.md)** — Top 15 questions (two containers, role differences, PDF watermarking, etc.)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — Development workflow, code standards, PR process
- **[CHANGELOG.md](./CHANGELOG.md)** — Version history
- **[INCIDENT-RESPONSE.md](./docs/INCIDENT-RESPONSE.md)** — Security incident handling, SLA tracking, remediation
- **[CHANGE-MANAGEMENT.md](./docs/CHANGE-MANAGEMENT.md)** — Code review, deployment gates, rollback
- **[SUPPORT-POLICY.md](./SUPPORT-POLICY.md)** — Support tiers, SLA, escalation
- **[SECURITY-EOL.md](./SECURITY-EOL.md)** — Version support lifecycle

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Contributing

See **[CONTRIBUTING.md](./CONTRIBUTING.md)**.

## Features

The portal implements a complete compliance-officer workflow:

- **Auth & RBAC** — role-based access for compliance officers, auditors, and SMEs.
- **Compliance API client** — talks to the compliance service (JWKS-verified signing).
- **Audit explorer** — browse and verify the tamper-evident audit chain.
- **Evidence package library** — assemble and export evidence bundles.
- **Gate decision workspace** — review and record gate decisions.
- **Auditor access controls** — scoped, time-boxed auditor provisioning.
- **DSR management** + **public DSR portal** — intake and cascade Data Subject Requests.
- **Incident console** — track and respond to incidents.
- **Model card registry** — govern deployed model cards.
- **Regulatory report generation** and **compliance dashboards**.
- **PDF export service** — SSRF-safe rendering + signing of reports.

See [`docs/`](docs/) for the API reference, architecture, configuration, and setup guides.
