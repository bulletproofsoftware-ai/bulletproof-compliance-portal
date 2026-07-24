# How to use — bulletproof-compliance-portal

Task-oriented walkthroughs organised by who you are. All internal-portal tasks
require an authenticated session (OIDC in staging/production; `dev-login` in
local development). The backing **compliance service** is the source of truth —
the portal is the human interface over it.

## Roles

| Role | Can do |
|------|--------|
| `admin` | Everything; auditor provisioning; oversight overrides |
| `compliance_officer` | DSR triage, gate decisions, incidents, reports, model-card sign-off |
| `auditor` | Scoped, time-limited download of evidence, audit chains, gate records |
| `sme` (domain expert) | Process-knowledge review queue; model-card domain review |
| `viewer` | Read-only dashboards and records |

---

## Data subject (public DSR portal)

No account is required. Open the public portal (default `http://localhost:8081`
locally, or the internet-facing nginx bind in production).

1. **Submit a request.** Choose the request type — access, erasure, portability,
   rectification, or automated-decision review (GDPR Articles 15–22) — at
   `/dsr/intake`. Provide the requested identity details. A CAPTCHA guards the
   form against automated abuse.
2. **Verify your identity.** The portal drives an identity-verification state
   machine; you may be asked to supply additional proof before the request is
   accepted.
3. **Track status.** Use the reference returned at submission to check progress.
   Requests are handled within GDPR's 30-day window.
4. **Receive evidence.** When fulfilled, you receive the response bundle through
   the delivery channel shown in the portal.

---

## Compliance officer (internal portal)

### Triage a DSR

- Go to `/dsr`. Review the queue, open a request, and drive it through the
  allowed status transitions (e.g. → `verified`, `identity_insufficient`,
  `identity_rejected`, `rejected`).
- **Separation of duties is enforced**: you cannot identity-verify a DSR that
  you submitted — the portal blocks it with a 409 and records an audit event.
- `rejected` requires a rejection reason; `verified` requires a verification
  method.

### Make a gate decision

- Go to `/gates`. Open a pending decision, review the attached evidence, and
  record your decision.
- Sensitive decisions require **MFA step-up**: you confirm a short-lived nonce
  (60-second lifetime, bound to you and this gate) before the decision commits.
  A rejected or replayed nonce is audited and refused.
- SoD applies to gate approvals as it does to DSRs.

### Manage an incident

- Go to `/incidents`. Track incidents against their SLA clock (e.g. a 72-hour
  regulatory notification deadline), add markdown notes (sanitised on render),
  and drive remediation to closure. Inbound events can arrive via the signed
  `/webhooks` endpoint.

### Generate a regulatory report

- Go to `/reports`. Assemble a report and approve it. **SoD**: you cannot
  approve a report you authored. Signing a report produces an **Ed25519-signed**
  delivery bundle anchored to a published JWKS, again gated by MFA step-up.

### Sign off a model card

- Go to `/models`. Work the annual sign-off queue; domain-expert review may be
  required before sign-off. Sign-off is MFA-gated.

### Read dashboards

- Go to `/dashboards` for SLA compliance, remediation progress, and risk views.

---

## External auditor

Auditors receive a **time-limited, scope-enforced** engagement provisioned by an
admin (see ADMINISTRATOR.md). Within scope you can:

- Download **evidence packages** — delivered as watermarked PDFs with *your*
  identity embedded in the watermark.
- Retrieve **audit chains** and **gate records** with cryptographic integrity
  verification.
- Pull **model cards** relevant to the engagement.

Access outside your granted scope, or after your engagement window closes, is
refused and audited.

---

## Domain expert (SME)

- Go to `/knowledge` to review the **process-knowledge verification queue** —
  knowledge candidates extracted from trajectories, sessions, or documents.
- For each candidate: inspect the YAML diff, then **approve**, **reject**, or
  **modify-and-approve**. A rationale of at least 30 characters is required, and
  modified YAML must pass validation before it is forwarded to the compliance
  service. Batch approve/reject is available (up to 100 candidates).

---

## Exporting PDFs

Most record views offer a signed PDF export via the `/export` service. Exports
are RBAC-checked (some components are auditor-only), rendered through an
SSRF-guarded URL fetcher, watermarked, and cryptographically signed. Export
actions are audited.

## API

Every route above is a normal HTTP endpoint. In non-public mode the OpenAPI docs
are served at `/docs` and `/redoc`, and the raw schema at `/openapi.json`. See
[`API.md`](API.md) for the endpoint reference.

## Related documents

- [`OVERVIEW.md`](OVERVIEW.md) — what the portal is and how the pieces fit
- [`ADMINISTRATOR.md`](ADMINISTRATOR.md) — provisioning, configuration, operations
- [`API.md`](API.md) — endpoint reference
- [`FAQ.md`](FAQ.md) — common questions

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
