# Changelog

All notable changes to the Compliance Portal project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- WI-14: Qdrant vector database integration for semantic search of process knowledge
- WI-16: Markdown proxy for fetching and rendering compliance documentation
- WI-17: X-Forwarded-* header support for trusted proxies and CORS configuration
- AMD-26: Support for behavioral event hooks (experimental; disabled by default)
- PDF watermark customization endpoint for audit evidence exports

### Changed
- **BREAKING**: COMPLIANCE_API_BASE_URL now requires full `/api/v1/compliance` path (previously auto-appended)
- Enhanced error messages for missing environment variables during startup
- Improved OIDC discovery error handling with fallback to static endpoints
- Session rotation now uses cryptographically secure random token generation
- PostgreSQL connection pool increased from 5 to 10 connections for better concurrency

### Deprecated
- Legacy API endpoints `/v1/audit/*` (use `/v2/audit/*` instead)
- Support for OIDC discovery disabled (`OIDC_DISCOVERY=false`) will be removed in v2.0

### Fixed
- AMD-02: SSRF protection now blocks all RFC 1918 private IP ranges
- Fixed race condition in MFA nonce validation (AMD-03)
- Corrected PII redaction pattern for European phone numbers (AMD-17)
- Fixed memory leak in Qdrant embedding cache (WI-14)
- Resolved issue where Redis TTL was not respected for session expiry

### Security
- CVE-2024-XXXX: Elevated privileges via OIDC group claim injection (patched)
- AMD-04: Ed25519 signing now uses RFC 8037 compliant key format
- AMD-10: mTLS certificate validation now enforces hostname matching

### Technical
- Upgraded dependencies:
  - fastapi 0.115.4 → 0.116.0
  - sqlalchemy 2.0.28 → 2.0.29
  - weasyprint 68.1 → 69.0
- Python 3.12 support verified on Alpine Linux
- Test suite now includes 505 tests (previously 485)

## [0.1.0] - 2024-04-27

### Added
- Initial Compliance Portal release
- **WI-02**: OIDC authentication with role-based access control (5 roles: admin, officer, auditor, sme, viewer)
- **WI-03**: Integration with compliance service via mTLS (AMD-10) and bearer token authentication
- **WI-04**: Gate Decision Workspace for management decisions with MFA step-up (AMD-03)
- **WI-05**: Audit Explorer for searching and analyzing audit events with IQMS immutability (REQ-CPL-039)
- **WI-06**: Incident Management for tracking and resolving compliance incidents
- **WI-07**: Model Card Registry for AI/ML model documentation and approval
- **WI-08**: Regulatory Report Generator with multi-framework support (ISO 27001, SOC 2, GDPR)
- **WI-09**: Public Data Subject Request portal with CAPTCHA protection and identity verification (AMD-01)
- **WI-10**: Auditor token management for external auditor provisioning
- **WI-11**: Compliance Dashboard with KPI visualization and trend analysis
- **WI-12**: PDF export service with cryptographic signing (Ed25519, AMD-04)
- **WI-13**: Evidence Package Library with integrity verification and SSRF protection (AMD-02)
- **WI-15**: Support for multiple deployment modes (internal/public/dual)

### Security
- **AMD-01**: Identity verification state machine for DSR submissions
- **AMD-02**: SSRF protection for PDF generation (WebayPrint SafeUrlFetcher)
- **AMD-03**: MFA step-up with nonce binding (60-second lifetime)
- **AMD-04**: Cryptographic signing of PDFs with Ed25519 and JWKS publication
- **AMD-05**: OIDC PKCE authorization code flow protection
- **AMD-06**: Auditor identity watermarking on evidence exports
- **AMD-07**: PDF digital signatures with timestamp verification
- **AMD-08**: Watermark opacity and anti-tampering measures
- **AMD-09**: Validation of compliance service certificate chain
- **AMD-10**: mTLS mutual authentication with compliance service (certificate pinning)
- **AMD-11**: OIDC group claim validation (prevent privilege escalation)
- **AMD-12**: Session token rotation on OIDC callback (prevent session fixation)
- **AMD-13**: Secure HTTP headers (CSP, X-Frame-Options, X-Content-Type-Options, etc.)
- **AMD-14**: Rate limiting per IP address for public DSR submissions
- **AMD-15**: Session rotation and max-age enforcement
- **AMD-16**: CORS origin validation with whitelist
- **AMD-17**: PII redaction in logs (email, phone, SSN, etc.)
- **AMD-18**: Subresource Integrity (SRI) for CDN-served assets
- **AMD-19**: CAPTCHA provider rotation (hCaptcha + reCAPTCHA fallback)
- **AMD-20**: Validation of Ed25519 signatures against published JWKS
- **AMD-21**: Protection against timing attacks in nonce verification
- **AMD-22**: Secure random token generation using SystemRandom
- **AMD-23**: Validation of Qdrant vector dimension matching
- **AMD-24**: Prevention of XXE attacks in XML-based evidence documents
- **AMD-25**: Database transaction isolation for concurrent gate decisions
- **AMD-26**: Behavioral event hook rate limiting (experimental)

### Compliance
- **REQ-CPL-001** through **REQ-CPL-039**: 39 compliance requirements implemented
- ISO 27001 Annex A controls for access management, cryptography, and incident response
- SOC 2 CC6 (Configuration) and CC7 (Monitoring) controls
- GDPR Article 25 (privacy by design) and Article 30 (data processing records)
- CCPA/CPRA data subject rights support (articles 1798.100-1798.120)

### Features
- **Two-container architecture** with network isolation (internal on port 8443, public on port 8444)
- **81 internal portal routes** across 14 routers (health, auth, audit, evidence, gate, auditor, DSR, incident, model-card, regulatory, dashboard, knowledge, economics, documentation)
- **8 public DSR portal routes** for data subject access requests and status tracking
- **505 comprehensive tests** with 85%+ code coverage
- FastAPI async application with Uvicorn ASGI server
- Jinja2 templating for HTML/PDF generation
- HTMX for interactive UI (no JavaScript required)
- SQLAlchemy ORM for database abstraction
- Redis for server-side session storage
- PostgreSQL for persistent data
- Qdrant for vector search (semantic analysis)
- WeasyPrint for PDF rendering with CSS support
- PyJWT for token generation and validation
- Cryptography library for Ed25519 signing

### Configuration
- 23 environment variables organized by functional domain
- Support for Docker Compose orchestration
- Kubernetes-ready manifest templates
- Systemd service file examples
- `.env.example` template for local development

### Documentation
- **README.md**: Project overview and quick start
- **ARCHITECTURE.md**: System design, data flows, security architecture
- **SETUP.md**: Development environment setup guide
- **INSTALLATION.md**: Production deployment procedures
- **API.md**: Complete API reference for all 89 routes
- **CONFIG.md**: Configuration variable reference
- **FAQ.md**: 15 frequently asked questions
- **SECURITY.md**: Security policy and vulnerability reporting (not shown)
- **docs/CISO-amendments-applied.md**: 26 security amendments detail

### Deployment
- **Docker**: Multi-stage build for lean production images
- **Docker Compose**: Complete stack (portal, redis, postgres, qdrant) for local development
- **Kubernetes**: StatefulSet with health probes and resource limits
- **Systemd**: Service file for bare-metal deployments
- Zero-downtime deployment strategy with rolling updates

### Operations
- Prometheus metrics endpoint `/metrics` for monitoring
- Liveness probe `/healthz` for container orchestration
- Structured JSON logging to stderr
- Request tracing with correlation IDs
- Audit trail with immutable IQMS database
- Automated backup and recovery procedures

### Known Limitations
- Compliance service (WI-03) is external dependency; graceful degradation if unavailable
- OIDC provider availability is critical; no local authentication fallback
- PDF watermarking requires SSRF-safe WeasyPrint configuration
- Vector search (Qdrant) is optional; portal functions without it

### Dependencies (25 direct)
- fastapi 0.115.4 — Web framework
- sqlalchemy 2.0.28 — ORM
- pydantic 2.6.1 — Data validation
- redis 5.0.1 — Session store
- psycopg 3.1.14 — PostgreSQL driver
- python-jose 3.3.0 — JWT handling
- cryptography 42.0.5 — Ed25519 signing
- pyjwt 2.8.1 — Token generation
- weasyprint 68.1 — PDF rendering
- jinja2 3.1.2 — Templating
- httpx 0.25.2 — HTTP client
- uvicorn 0.27.0 — ASGI server
- python-dotenv 1.0.0 — .env parsing
- pytest 7.4.4 — Testing framework
- pytest-asyncio 0.23.1 — Async test support

### Python Version
- **Required**: Python 3.12 or higher
- **Tested**: 3.12.0 through 3.12.2
- **Not Supported**: Python 3.11 or earlier

### Platforms
- **Development**: macOS 12+, Ubuntu 20.04+, Debian 11+
- **Production**: Ubuntu 20.04+, Alpine Linux 3.18+, Amazon Linux 2023+
- **Containers**: Docker 20.10+, Podman 4.0+, containerd 1.6+

### Contributors
- Core team: the maintainers

---

## Semantic Versioning

This project follows [Semantic Versioning](https://semver.org/):

```
MAJOR.MINOR.PATCH
  ↓     ↓     └─ Bug fixes (0.1.1, 0.1.2, etc.)
  ↓     └────── New features (0.2.0, 0.3.0, etc.)
  └──────────── Breaking changes (1.0.0, 2.0.0, etc.)
```

- **MAJOR**: Breaking API changes, database migrations
- **MINOR**: New features, non-breaking enhancements
- **PATCH**: Bug fixes, security patches

## Release Policy

### Versioning Schedule
- **Major versions** (e.g., 1.0, 2.0): Annually or when breaking changes require
- **Minor versions** (e.g., 1.1, 1.2): Monthly or when feature set grows
- **Patch versions** (e.g., 1.0.1, 1.0.2): As-needed for critical fixes

### Support Lifecycle

| Version | Released | Support End | Security End |
|---------|----------|-------------|--------------|
| 0.x.x | 2024-04-27 | 2024-10-27 | 2024-12-31 |
| 1.0.x | TBD | TBD | TBD |

Early-stage releases (0.x.x) receive 6 months of support; production releases (1.0+) receive 2 years of support.

### Pre-release Versions
- **Alpha** (e.g., 0.2.0-alpha.1): Unstable, features may change
- **Beta** (e.g., 0.2.0-beta.1): Feature-complete, testing phase
- **RC** (e.g., 0.2.0-rc.1): Release Candidate, minimal changes

Pre-release versions are not recommended for production use.

## Notes for Contributors

### Updating the Changelog

When adding changes:

1. **Add entries to Unreleased section** (not directly to version)
2. **Use proper categories**: Added, Changed, Deprecated, Removed, Fixed, Security, Technical
3. **Reference work items**: WI-XX for feature work, AMD-XX for security amendments
4. **Include breaking changes prominently** with **BREAKING** marker
5. **Include security fixes prominently** with security impact description
6. **Link to CVE numbers** if applicable

### Release Process

Before releasing a new version:

1. **Update version** in `src/portal/__init__.py`
2. **Create changelog entry** with new version number and date
3. **Run full test suite** and verify all 505+ tests pass
4. **Generate SBOM** with `syft . -o cyclonedx-json=sbom.json`
5. **Sign release** with Ed25519 key
6. **Create GitHub release** with changelog excerpt
7. **Deploy** to staging and production

See **INSTALLATION.md** section "Deployment Verification" for complete release procedures.

## Archive

See git history for older versions: `git log --oneline --all`
