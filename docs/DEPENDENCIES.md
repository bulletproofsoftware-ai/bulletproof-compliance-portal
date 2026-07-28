# Dependency Management

This document describes how Compliance Portal selects, obtains, maintains, and tracks its dependencies throughout their lifecycle.

## Table of Contents

1. [Overview](#overview)
2. [Dependency Policy](#dependency-policy)
3. [Approval Process](#approval-process)
4. [Current Dependencies](#current-dependencies)
5. [Supply Chain Security](#supply-chain-security)
6. [Update Strategy](#update-strategy)
7. [Vulnerability Management](#vulnerability-management)
8. [License Compliance](#license-compliance)

## Overview

The Compliance Portal has **25 direct runtime dependencies** plus **8 development-only dependencies**, organized by functional domain:

| Category | Count | Status |
|----------|-------|--------|
| Web framework & routing | 3 | Current |
| Data validation & ORM | 3 | Current |
| Authentication & crypto | 4 | Current |
| Caching & sessions | 2 | Current |
| Database drivers | 2 | Current |
| HTTP & networking | 2 | Current |
| PDF rendering | 1 | Current |
| Templating | 1 | Current |
| Environment & config | 1 | Current |
| ASGI server | 1 | Current |
| Development tools | 8 | Current |

All dependencies are pinned to exact versions in `requirements.txt` for reproducibility and supply chain security.

## Dependency Policy

### Selection Criteria

New dependencies are evaluated against these mandatory criteria:

#### 1. License Compatibility

| License | Status | Notes |
|---------|--------|-------|
| MIT | **Approved** | Permissive; no restrictions |
| Apache-2.0 | **Approved** | Patent grant included |
| BSD-2-Clause | **Approved** | Permissive |
| BSD-3-Clause | **Approved** | Permissive |
| ISC | **Approved** | Permissive |
| Unlicense | **Approved** | Public domain |
| Python Software Foundation License | **Approved** | Python ecosystem standard |
| MPL-2.0 | **Conditional** | File-level copyleft; requires legal review |
| LGPL-2.1/3.0 | **Conditional** | Dynamic linking only; requires review |
| GPL-2.0/3.0 | **Not Approved** | Copyleft viral license |
| AGPL-3.0 | **Not Approved** | Network copyleft incompatible |
| Proprietary | **Not Approved** | Closed source; legal liability |
| No License | **Not Approved** | Undefined rights; legal risk |

#### 2. Security & Maintenance

- **No critical/high CVEs** in current or previous 2 versions
- **Active maintenance** (commits in last 6 months)
- **Secure development** (code review, issue tracking, security contact)
- **Community reputation** (used by 50+ projects OR by known companies)

#### 3. Technical Fit

- **API stability** (no major breaking changes in last 12 months)
- **Performance** (acceptable latency/memory overhead)
- **Compatibility** (Python 3.12+, no obsolete dependencies)
- **Minimal transitive dependencies** (prefer few dependencies over many)

#### 4. Support & Documentation

- **Clear documentation** (API docs, examples, community resources)
- **Active community** (issue response time < 2 weeks)
- **Maintenance history** (longstanding or actively maintained new project)

### Approval Process

To add a new dependency:

1. **Justify** the dependency in the PR description
   - What problem does it solve?
   - What alternatives were considered?
   - Why is this the best choice?

2. **Evaluate** against the criteria above
   - Check license compatibility
   - Scan for CVEs (use Trivy or Grype)
   - Verify maintenance activity (GitHub issues, recent commits)
   - Review API stability

3. **Security scan** via automated pipeline
   - Run `pip-audit` to detect known vulnerabilities
   - Run `license-checker` to verify license compliance

4. **Code review**
   - Verify actual usage in code (not just declared)
   - Ensure proper error handling around the dependency
   - Check if the dependency can be deferred (optional/lazy loading)

5. **Merge** to main (requires approval from at least 2 maintainers)

Once merged, the dependency is automatically tracked and monitored for:
- Security vulnerabilities
- Update availability
- License compliance

## Current Dependencies

### Runtime Dependencies (25 direct)

Dependencies required to run the application in production.

#### Web Framework & Routing (3)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **fastapi** | 0.115.4 | MIT | Modern ASGI web framework |
| **uvicorn** | 0.27.0 | BSD-3 | ASGI application server |
| **starlette** | 0.38.5 | BSD-3 | HTTP utilities (pulled in by FastAPI) |

FastAPI is the core web framework, providing:
- Async/await support for high concurrency
- Automatic OpenAPI/Swagger documentation
- Data validation via Pydantic
- Dependency injection system
- Built-in CORS, authentication, background tasks

#### Data Validation & ORM (3)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **pydantic** | 2.6.1 | MIT | Data validation and serialization |
| **sqlalchemy** | 2.0.28 | MIT | SQL toolkit and ORM |
| **alembic** | 1.13.1 | MIT | Database migrations |

Pydantic validates request/response data, ensuring type safety and preventing injection attacks. SQLAlchemy abstracts database queries, supporting PostgreSQL, SQLite, and others.

#### Authentication & Cryptography (4)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **cryptography** | 49.0.0 | Apache-2.0/BSD | Cryptographic algorithms (Ed25519, ECDSA, etc.) |
| **authlib** | 1.7.2 | BSD-3-Clause | OAuth 2.0 / OIDC client — the actual auth implementation (`src/portal/auth/oidc.py`) |
| **joserfc** | 1.7.4 | BSD-3-Clause | JOSE (JWT/JWS/JWE) primitives, pulled in by Authlib |
| **itsdangerous** | 2.2.0 | BSD-3-Clause | Signed session cookies and tokens |

> [!note] Corrected 2026-07-27
> This table previously listed `pyjwt`, `python-jose`, and `passlib`. **None of
> the three are dependencies of this project** — `pyjwt` and `passlib` were never
> declared, and `python-jose` was declared but never imported anywhere, so it was
> removed (it was the sole path to `ecdsa`, which carried two HIGH findings with
> no fix available, including CVE-2024-23342). `cryptography` was also listed at
> 42.0.5; the pinned version is 49.0.0.
>
> OIDC is implemented with **Authlib**, which depends on `cryptography` and
> `joserfc` — not `ecdsa`. If JWT work is added later, use Authlib (already
> present) or `pyjwt[crypto]`; both avoid the unmaintained `ecdsa` package.

These packages provide:
- OIDC authentication flow (WI-02)
- Ed25519 cryptographic signing (AMD-04)
- Session token generation (AMD-15)
- MFA nonce validation (AMD-03)

#### Caching & Session Management (2)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **redis** | 5.0.1 | MIT | Redis Python client |
| **aioredis** | 2.0.1 | MIT | Async Redis client |

Redis stores user sessions (server-side), providing:
- Session persistence across container restarts
- Cache for OIDC discovery documents
- Token revocation lists (future use)

#### Database Drivers (2)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **psycopg** | 3.1.14 | LGPL-3 | PostgreSQL async driver (asyncpg) |
| **asyncpg** | 0.28.0 | Apache-2.0 | PostgreSQL native async driver |

Provides async connectivity to PostgreSQL for:
- Audit event queries (WI-05)
- DSR submission storage (WI-09)
- Compliance data views (WI-13)

Note: `psycopg` wraps `asyncpg` with connection pooling and better error handling.

#### HTTP & Networking (2)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **httpx** | 0.25.2 | BSD-3 | Async HTTP client |
| **requests** | 2.31.0 | Apache-2.0 | Sync HTTP client (fallback) |

Used for:
- OIDC provider discovery requests
- Compliance service API calls (WI-03)
- External markdown proxy requests (WI-16)

#### PDF Rendering (1)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **weasyprint** | 68.1 | BSD-3 | HTML to PDF conversion |

Renders evidence packages and compliance reports to PDF with:
- CSS-based styling (watermarks, headers, footers)
- Safe URL fetching (SSRF protection, AMD-02)
- Metadata embedding (signatures, audit trail)

#### Templating (1)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **jinja2** | 3.1.2 | BSD-3 | HTML/text templating |

Used for:
- HTML rendering (user-facing pages)
- Email templates (DSR notifications)
- PDF template rendering (evidence reports, WI-12)

#### Environment & Configuration (1)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **python-dotenv** | 1.0.0 | BSD-3 | Load .env files into environment |

Loads environment variables from `.env` file in development mode only (not used in production).

#### Vector Search (optional, installed)

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **qdrant-client** | 2.7.0 | Apache-2.0 | Qdrant vector database client |

Used for semantic search (WI-14):
- Process knowledge retrieval
- Evidence similarity matching
- Embedding operations

**Note**: Can be optional; Qdrant is only queried if `QDRANT_URL` is configured.

### Development Dependencies (8)

Dependencies used for testing, linting, and code quality, not shipped to production.

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **pytest** | 7.4.4 | MIT | Test framework |
| **pytest-asyncio** | 0.23.1 | Apache-2.0 | Async test support |
| **pytest-cov** | 4.1.0 | MIT | Coverage reporting |
| **black** | 24.1.1 | MIT | Code formatter |
| **flake8** | 7.0.0 | MIT | Linter |
| **mypy** | 1.8.0 | MIT | Type checker |
| **isort** | 5.13.2 | MIT | Import sorter |
| **pytest-xdist** | 3.5.0 | MIT | Parallel test execution |

## Supply Chain Security

### Dependency Verification

All dependencies are verified via:

#### 1. Package Signature Verification

Python packages on PyPI can be signed. The portal verifies:

```bash
# Install with signature verification (if available)
pip install --require-hashes -r requirements.txt
```

Requirements file includes hashes:

```
fastapi==0.115.4 --hash=sha256:a1b2c3d4e5f6... --hash=sha256:x9y8z7...
sqlalchemy==2.0.28 --hash=sha256:...
```

#### 2. Vulnerability Scanning

Dependencies are scanned daily for CVEs:

```bash
# Scan installed packages
pip-audit

# Scan requirements file
pip-audit --requirement requirements.txt

# Example output:
# Found 0 known security vulnerabilities in 25 packages
```

During CI/CD:
- Every PR runs `pip-audit` (blocks merge if vulns found)
- Main branch scanned daily; alerts sent if issues found

#### 3. License Scanning

License compliance is checked automatically:

```bash
# Check licenses of all dependencies
pip-license --format=markdown

# Example output:
# Package Name | Version | License
# fastapi | 0.115.4 | MIT
# sqlalchemy | 2.0.28 | MIT
```

Approved licenses are defined in `src/portal/config.py:APPROVED_LICENSES`.

#### 4. Software Bill of Materials (SBOM)

An SBOM is generated for every release:

```bash
# Generate SBOM
syft . -o cyclonedx-json=sbom.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.json
```

The SBOM is included in GitHub releases and provides:
- Complete inventory of dependencies
- Version numbers and hashes
- License information
- Vulnerability baseline at release time

### Pinned Versions

All dependencies are pinned to exact versions:

```bash
# ✅ CORRECT (pinned)
fastapi==0.115.4
sqlalchemy==2.0.28

# ❌ WRONG (not pinned; causes non-determinism)
fastapi>=0.115.0
sqlalchemy~=2.0
```

Benefits of pinning:
- Reproducible builds (same code = same dependencies)
- No surprise breaking changes
- Deterministic security vulnerability baseline
- Easier debugging (known dependency versions)

Downsides of pinning:
- Manual updates required (but automated via Dependabot)
- Potential security vulnerabilities if not updated

To address the downside, automated dependency updates are enabled:

### Automated Dependency Updates (Dependabot)

GitHub Dependabot creates automatic PRs for dependency updates:

**Update frequency**:
- Security patches: Immediate (auto-merged if tests pass)
- Minor updates: Weekly
- Major updates: Manual review required

**Example Dependabot PR**:

```
Title: "Bump fastapi from 0.115.4 to 0.115.5"
Body: "Automated dependency update via Dependabot"

Changes:
- fastapi: 0.115.4 → 0.115.5 (patch; security fix for CVE-2024-XXXX)

CI Status: ✅ All tests passing

Auto-merge: ✅ (security patch + all tests pass)
```

Manual review is required for:
- Major version upgrades (may have breaking changes)
- License changes
- New transitive dependencies > 5

## Update Strategy

### Patch Updates (e.g., 0.115.4 → 0.115.5)

**When**: Weekly (or immediately for security patches)
**Review**: Automated (if all tests pass)
**Auto-merge**: Yes (for security patches)
**Breaking changes**: None (by definition of semver)

Patch updates contain bug fixes and security patches with no API changes.

**Example**:
```bash
# Before
fastapi==0.115.4

# After (security patch)
fastapi==0.115.5  # Fixes: CVE-2024-XXXX

# Action: Auto-merge, deploy to production
```

### Minor Updates (e.g., 0.114.x → 0.115.x)

**When**: Monthly (or as-needed for new features)
**Review**: Required (changelog review)
**Auto-merge**: Conditional (if tests pass + no license changes)
**Breaking changes**: None (new features, backward compatible)

Minor updates add features but maintain API compatibility.

**Example**:
```bash
# Before
fastapi==0.114.0

# After
fastapi==0.115.4  # Adds: new features, performance improvements

# Action: Review changelog, test thoroughly, merge if safe
```

### Major Updates (e.g., 1.x → 2.x)

**When**: As-needed (typically annually)
**Review**: Extensive (breaking changes must be analyzed)
**Auto-merge**: Never (requires manual testing)
**Breaking changes**: Likely (API changes, deprecated features removed)

Major updates often require code changes in the application.

**Example**:
```bash
# Before
sqlalchemy==2.0.28

# After
sqlalchemy==3.0.0  # Breaking changes: ORM API redesigned

# Action: Review migration guide, update application code, test extensively, manual approval
```

## Vulnerability Management

### Vulnerability Response Timeline

When a CVE (Common Vulnerabilities and Exposures) is published for a dependency:

| Severity | Notification | Response Time | Update Timeline |
|----------|--------------|---------------|-----------------|
| **Critical** | Immediate | Within 24 hours | Patch released within 7 days |
| **High** | Within 24 hours | Within 7 days | Update applied within 14 days |
| **Medium** | Within 48 hours | Within 30 days | Update applied within 30 days |
| **Low** | Weekly summary | Within 90 days | Update applied within 90 days |

### Handling Vulnerable Dependencies

When a vulnerability is discovered:

1. **Detection**: Automated scanning (Trivy, Grype, pip-audit) detects the vulnerability

2. **Assessment**: Security team evaluates:
   - Does the vulnerability affect our code path?
   - How severe is it? (CVSS score)
   - Is there a patched version available?

3. **Mitigation**: Either:
   - **Option A**: Upgrade to patched version (preferred)
   - **Option B**: Downgrade to an older patched version
   - **Option C**: Patch the dependency locally (if no upstream fix available)
   - **Option D**: Accept risk with documented justification (rare)

4. **Deployment**: Updated application is deployed to production

5. **Verification**: Vulnerability scan confirms vulnerability is no longer detected

### Example Vulnerability Response

```bash
# CVE-2024-XXXX detected in fastapi 0.115.0-0.115.3
$ pip-audit
Found 1 known security vulnerability in fastapi==0.115.3
  Vulnerability in fastapi
    IDs: CVE-2024-XXXX
    Severity: HIGH
    Fix version: 0.115.4 or later

# Update requirements.txt
fastapi==0.115.4  # Contains fix for CVE-2024-XXXX

# Test
$ make test  # All 505 tests pass

# Deploy
$ git commit -m "fix: patch CVE-2024-XXXX in fastapi"
$ git push  # Automated deployment to production

# Verify
$ pip-audit  # No vulnerabilities found
```

## License Compliance

### License Inventory

All dependencies and their licenses are tracked in `THIRD_PARTY_LICENSES.md`:

```markdown
# Third-Party Licenses

## Runtime Dependencies

### fastapi (0.115.4) — MIT License
[Full license text...]

### sqlalchemy (2.0.28) — MIT License
[Full license text...]

...
```

### License Compliance Checks

Before each release:

1. **Generate inventory**: `pip-license > THIRD_PARTY_LICENSES.md`
2. **Review licenses**: Ensure all licenses are on approved list
3. **Check for GPL/AGPL**: Ensure no viral licenses were added
4. **Commit**: Commit updated license file

### GPL/AGPL Handling

Compliance Portal intentionally avoids GPL and AGPL dependencies because:

- **GPL**: Requires source code disclosure if distributed
- **AGPL**: Requires source code disclosure if used as a service

If a dependency with GPL/AGPL is discovered:

1. **Evaluate alternatives**: Can we find a compatible alternative?
2. **Assess impact**: What's the cost of not using this dependency?
3. **Legal review**: Consult legal team if uncertain
4. **Decide**: Include (if legal permits) or find alternative

### Dynamic License Scanning

In production, the application can expose its dependency tree and licenses:

```bash
# View dependency licenses (authorized personnel only)
curl https://portal.internal/admin/dependencies/licenses

# Response:
# {
#   "fastapi": {"version": "0.115.4", "license": "MIT"},
#   "sqlalchemy": {"version": "2.0.28", "license": "MIT"},
#   ...
# }
```

This endpoint is only available to administrators and is used during compliance audits.

## Dependency Monitoring

### Active Monitoring

Dependencies are continuously monitored for:

- **Security vulnerabilities** (via Trivy, Grype, pip-audit)
- **Update availability** (via Dependabot, renovate)
- **Maintenance health** (commits, issue response time)
- **Community activity** (GitHub stars, downloads, issues)

### Monitoring Dashboard

Maintainers have access to a dependency dashboard showing:

```
Dependency Health Overview
═════════════════════════════════════════════════════════════

fastapi 0.115.4 (MIT)
  Status: ✅ Up to date
  Maintenance: Active (commit 1 week ago)
  Security: ✅ No known vulnerabilities
  Popularity: ⭐⭐⭐⭐⭐ (60K+ stars)
  
sqlalchemy 2.0.28 (MIT)
  Status: ⚠️ Update available (2.0.29)
  Maintenance: Active (commit 3 days ago)
  Security: ✅ No known vulnerabilities
  Popularity: ⭐⭐⭐⭐⭐ (40K+ stars)

qdrant-client 2.7.0 (Apache-2.0)
  Status: ✅ Up to date
  Maintenance: Active (commit 2 weeks ago)
  Security: ✅ No known vulnerabilities
  Popularity: ⭐⭐⭐⭐ (3.5K stars)

...
```

### Quarterly Reviews

Every 3 months, the maintainers review:

1. **Deprecated packages**: Any dependencies deprecated upstream?
2. **Unused packages**: Any dependencies no longer used in code?
3. **Update backlog**: Major updates pending? Should we upgrade?
4. **Security posture**: Any trending vulnerabilities?
5. **License changes**: Any license updates we need to track?

Results of the quarterly review are documented in a GitHub issue and tracked in project planning.

## Transitive Dependency Management

The 25 direct dependencies pull in additional **transitive dependencies** (dependencies of dependencies).

**Transitive dependency tree** (example):

```
fastapi 0.115.4
  ├── starlette 0.38.5 (included)
  ├── pydantic 2.6.1 (also direct)
  ├── typing-extensions 4.9.0 (transitive)
  └── ... (2 more)

sqlalchemy 2.0.28
  ├── greenlet 3.0.3 (transitive)
  └── ... (no others)

...

Total transitive dependencies: ~85
```

**Transitive dependency monitoring**:

- All transitive dependencies are scanned for vulnerabilities
- Transitive dependencies are not pinned (managed by package maintainers)
- If a transitive dependency becomes problematic, we evaluate:
  - Can we downgrade the direct dependency?
  - Can we pin the transitive dependency explicitly?
  - Should we replace the direct dependency entirely?

## Dependency Policies

### Strict Policies (Always enforced)

- ✅ **All dependencies pinned** to exact versions
- ✅ **No GPL/AGPL** licenses
- ✅ **Security scanning** on every PR
- ✅ **License compliance** checked before release
- ✅ **CVE response** within 24 hours for critical issues

### Guidelines (Recommended best practices)

- 📋 **Prefer established packages** (used by 50+ projects)
- 📋 **Minimize dependency count** (prefer 1 large package over 3 small ones)
- 📋 **Lazy-load optional dependencies** (load Qdrant only if configured)
- 📋 **Regular updates** (review Dependabot PRs weekly)
- 📋 **Quarterly audits** (review unused/deprecated dependencies)

## Reporting Dependency Issues

Found an issue with a dependency?

1. **Security vulnerability**: Email security@acme.io (do not create public issue)
2. **License concern**: Create confidential issue (mark confidential)
3. **Compatibility problem**: Create public issue with full reproduction steps
4. **Maintenance concern** (dependency no longer maintained): Discuss in team channel

See **SECURITY.md** for vulnerability disclosure policy.
