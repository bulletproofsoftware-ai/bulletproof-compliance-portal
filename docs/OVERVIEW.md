# Overview — bulletproof-compliance-portal

A FastAPI compliance and governance portal for managing Data Subject Requests
(DSRs), audit trails, evidence packages, gate decisions, incidents, model-card
governance, and regulatory reports — with role-based access control and
comprehensive audit logging. It surfaces a backing **compliance service** to
humans who are not operators: compliance officers, external auditors, data
subjects, and domain experts.

## The three surfaces

The same application factory (`src/portal/main.py:create_app`) backs two
distinct deployments, plus a scoped auditor path:

| Surface | App | Purpose |
|---------|-----|---------|
| **Internal portal** | `portal.main:app` (mode `internal`) | Compliance-officer workspace: DSR triage, evidence review, gate decisions, incident management, model-card governance, regulatory reporting, auditor provisioning, dashboards, documentation portal. |
| **Public DSR portal** | `dsr_portal.main:app` (mode `public`) | Self-service intake for data subjects (GDPR Articles 15–22): access, erasure, portability, rectification, and automated-decision review. No account required. |
| **Auditor access** | Scoped routes on the internal app | Time-limited, scope-enforced download of evidence packages, audit chains, gate records, and model cards with cryptographic integrity verification. |

The public portal is deliberately a smaller attack surface: it mounts only the
DSR intake routes and re-uses the shared config/logging/middleware — the
internal routers (audit, evidence, gates, auditor admin, etc.) are **not**
registered when the app is built in `public` mode.

## Capabilities

- **DSR management** — submission, identity verification (a dedicated state
  machine), status tracking, and evidence delivery within GDPR's 30-day window.
- **Gate decision workspace** — evidence review, stakeholder notification, MFA
  step-up per decision, and separation-of-duties (SoD) enforcement.
- **Audit explorer** — search, filter, and stream/download audit trails with
  integrity verification.
- **Evidence package library** — watermarked PDF delivery with the requesting
  auditor's identity embedded.
- **Auditor access controls** — time-limited tokens, scope enforcement, and a
  separate admin path for engagement provisioning.
- **Incident console** — SLA tracking (e.g. a 72-hour regulatory notification
  clock), audit emission, and remediation workflows.
- **Model-card registry** — annual sign-off tracking and domain-expert review
  queues.
- **Regulatory report generation** — Ed25519-signed delivery bundles with JWKS
  anchors.
- **Compliance dashboards** — SLA compliance, remediation progress, risk views.
- **Process-knowledge verification** — a domain-expert review queue for
  extracted knowledge candidates.
- **PDF export service** — safe URL rendering (SSRF-guarded), watermarking, and
  cryptographic signatures.
- **Project documentation portal** — read-only architecture/coverage/cost views.

## Architecture at a glance

```
            data subjects                 compliance officers / auditors / SMEs
                  │                                     │
        ┌─────────▼──────────┐              ┌───────────▼───────────┐
        │  Public DSR portal │              │   Internal portal     │
        │  dsr_portal.main   │              │   portal.main         │
        │  (intake only)     │              │   (full workspace)    │
        └─────────┬──────────┘              └───────────┬───────────┘
                  │        shared config / middleware   │
                  └──────────────────┬──────────────────┘
                                     │  HTTP (bearer / mTLS)
                             ┌───────▼────────┐
                             │  Compliance    │   backing service (separate repo)
                             │  service API   │   — source of truth for records
                             └───────┬────────┘
                                     │
                        Redis (sessions) · PostgreSQL (persistence)
```

Both portals sit behind an nginx reverse proxy. The internal portal is intended
to run on a private/overlay network (not directly exposed to the internet); the
public portal is exposed behind a WAF. See [`INSTALLATION.md`](INSTALLATION.md)
and [`../docker/README.md`](../docker/README.md).

### Security middleware stack

Every request passes through a fixed middleware chain (registered in reverse so
runtime order matches the spec): forwarded-header handling → request ID →
security headers (CSP/HSTS/X-Frame-Options) → CORS → rate limiting →
CSRF → audit logging → behavioral hook. Authentication is OIDC (PKCE
authorization-code flow) with role-based access control across five roles:
`admin`, `compliance_officer`, `auditor`, `sme`, `viewer`.

## Route map (internal portal)

Routers are mounted at these prefixes (see `src/portal/routers/`):

| Prefix | Router | Area |
|--------|--------|------|
| `/healthz`, `/readyz` | health | Liveness / readiness |
| `/auth/*` | oidc | OIDC login/callback (+ dev-login in development) |
| `/home` | home | Landing / navigation |
| `/audit` | audit | Audit explorer + export |
| `/evidence` | evidence | Evidence package library |
| `/gates` | gates | Gate decision workspace |
| `/admin/auditor-engagements` | auditor_admin | Auditor provisioning |
| `/dsr` | dsr | DSR triage (internal side) |
| `/incidents`, `/webhooks` | incidents | Incident console + inbound webhook |
| `/models` | model_cards | Model-card registry |
| `/reports` | reports | Regulatory report generation |
| `/dashboards` | dashboards | Compliance dashboards |
| `/knowledge` | process_knowledge | Process-knowledge review queue |
| `/outcomes` | outcomes | Outcome tracking |
| `/projects` | project_docs | Read-only documentation portal |
| `/export` | export | PDF export service |
| `/metrics` | prometheus | Metrics exposition |

The public DSR portal mounts only its intake routes under `/dsr` plus health.

## Where to go next

- [`INSTALLATION.md`](INSTALLATION.md) — install & run (local, Docker Compose)
- [`HOW-TO-USE.md`](HOW-TO-USE.md) — task-oriented walkthroughs by role
- [`ADMINISTRATOR.md`](ADMINISTRATOR.md) — operate, configure, and secure it
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — full system design
- [`API.md`](API.md) — endpoint reference
- [`CONFIG.md`](CONFIG.md) — every configuration variable
- [`SBOM.md`](SBOM.md) · [`scan/scan-report.md`](scan/scan-report.md) — supply chain & security

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
