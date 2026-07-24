# Changelog

All notable changes to the Compliance Portal are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Remediated all critical and high findings from the security scan
  (see [`docs/scan/scan-report.md`](docs/scan/scan-report.md)) — dependency CVEs
  bumped to their first patched versions and the code-lint findings resolved.
  Result: **0 critical / 0 high**.
- Dependency upgrades to patched versions:
  - `python-jose` 3.3.0 → 3.5.0 (CVE-2024-33663 ECDSA key algorithm confusion)
  - `authlib` 1.3.2 → 1.7.2 (CVE-2026-27962 JWK header-injection auth bypass,
    CVE-2026-28498 forged OIDC ID tokens, CVE-2026-28490 JWE padding oracle)
  - `cryptography` 43.0.3 → 49.0.0 (bundled-OpenSSL advisory; SECT-curve
    subgroup attack CVE-2026-26007)
  - `starlette` 0.41.2 → 1.3.1 (form-limit DoS, StaticFiles UNC SSRF,
    Range-header DoS)
  - `orjson` 3.10.10 → 3.11.9 (deeply-nested-JSON recursion DoS)
  - `python-multipart` 0.0.17 → 0.0.31 (quadratic-parsing and
    unbounded-header DoS)
  - `fastapi` 0.115.4 → 0.140.0 (required to permit the patched `starlette`)

### Changed
- Best-effort audit emissions on security-refusal paths now use
  `contextlib.suppress` instead of bare `try/except/pass`.
- `pyproject.toml` license metadata aligned to Apache-2.0 to match `LICENSE`.

## [0.1.0] — 2026-04-27

Initial Compliance Portal release.

### Added
- **OIDC authentication** with role-based access control across five roles:
  `admin`, `compliance_officer`, `auditor`, `sme`, `viewer`.
- **Compliance service integration** over HTTP with bearer-token and optional
  mutual-TLS authentication.
- **Gate Decision Workspace** — management decisions with MFA step-up and
  separation-of-duties enforcement.
- **Audit Explorer** — search, filter, and export audit events with integrity
  verification.
- **Incident Management** — SLA-tracked incident console with remediation
  workflows and a signed inbound webhook.
- **Model Card Registry** — model documentation with annual sign-off tracking
  and domain-expert review.
- **Regulatory Report Generator** — multi-framework support (ISO 27001, SOC 2,
  GDPR) with Ed25519-signed delivery bundles.
- **Public Data Subject Request portal** — GDPR Articles 15–22 intake with
  CAPTCHA protection and identity verification.
- **Auditor engagement management** — time-limited, scope-enforced external
  auditor provisioning.
- **Compliance Dashboards** — KPI visualisation and trend analysis.
- **Evidence Package Library** — watermarked delivery with integrity
  verification and SSRF-guarded rendering.
- **Process-knowledge verification queue** — SME review of extracted knowledge
  candidates.
- **PDF export service** — safe URL rendering, watermarking, and cryptographic
  signing.
- **Multiple deployment modes** — internal, public, or both.

### Security controls
- Identity-verification state machine for DSR submissions.
- SSRF protection for PDF generation (blocks RFC 1918 and other private ranges).
- MFA step-up with short-lived nonce binding.
- Ed25519 PDF/report signing with JWKS publication.
- OIDC PKCE authorization-code flow; group-claim validation to prevent
  privilege escalation; session-token rotation on callback to prevent fixation.
- Auditor-identity watermarking on evidence exports.
- mTLS mutual authentication with the compliance service (certificate-chain and
  hostname validation).
- Secure HTTP headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
- Per-IP rate limiting for public DSR submissions.
- CORS origin allow-listing.
- PII redaction in logs (email, phone, and similar).
- Timing-attack-resistant nonce verification and secure random token generation.

### Compliance
- ISO 27001 Annex A controls for access management, cryptography, and incident
  response.
- SOC 2 CC6 (configuration) and CC7 (monitoring) controls.
- GDPR Article 25 (privacy by design) and Article 30 (records of processing).
- CCPA/CPRA data-subject-rights support.

### Architecture
- Two-app design (internal workspace + public DSR portal) from one FastAPI
  factory, with network isolation.
- FastAPI + Uvicorn (ASGI), Jinja2 templating, HTMX for interactive UI.
- SQLAlchemy over PostgreSQL for persistence; Redis for server-side sessions.
- WeasyPrint for PDF rendering; `cryptography` for Ed25519 signing.
- Prometheus metrics (`/metrics`), liveness (`/healthz`) and readiness
  (`/readyz`) probes, and structured JSON logging with correlation IDs.

### Documentation
- README, `docs/OVERVIEW.md`, `docs/INSTALL.md` / `docs/INSTALLATION.md`,
  `docs/HOW-TO-USE.md`, `docs/ADMINISTRATOR.md`, `docs/ARCHITECTURE.md`,
  `docs/API.md`, `docs/CONFIG.md`, `docs/FAQ.md`, `docs/SBOM.md`, and the
  security scan report under `docs/scan/`.

### Known limitations
- The compliance service is an external dependency; the portal degrades
  gracefully when it is unavailable.
- OIDC provider availability is required outside development (a `dev-login`
  route exists for local use only).

### Requirements
- **Python**: 3.12 or higher.

---

## Contributing to the changelog

When adding changes:

1. Add entries to the **Unreleased** section (not directly to a released version).
2. Use the standard categories: Added, Changed, Deprecated, Removed, Fixed,
   Security.
3. Mark breaking changes with a **BREAKING** prefix.
4. Describe the security impact of security fixes, and link CVE/GHSA identifiers
   where applicable.

Older versions: see the git history (`git log --oneline`).
