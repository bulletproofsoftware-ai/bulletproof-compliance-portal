# Software Bill of Materials (SBOM)

This document describes the Software Bill of Materials (SBOM) for Compliance Portal (PRD-19), including component inventory, dependency management, licensing compliance, and vulnerability tracking.

## Table of Contents

1. [Overview](#overview)
2. [SBOM Generation](#sbom-generation)
3. [Component Inventory](#component-inventory)
4. [Dependency Management](#dependency-management)
5. [License Compliance](#license-compliance)
6. [Vulnerability Tracking](#vulnerability-tracking)
7. [Supply Chain Security](#supply-chain-security)
8. [SBOM Distribution](#sbom-distribution)

## Overview

A Software Bill of Materials (SBOM) is a comprehensive, machine-readable inventory of all components, libraries, and dependencies included in the Compliance Portal. The SBOM serves multiple critical purposes:

- **Security**: Identify known vulnerabilities in dependencies
- **Compliance**: Verify license compatibility and track third-party software
- **Supply Chain**: Demonstrate software provenance and component integrity
- **Operations**: Support incident response (identify systems affected by vulnerabilities)

### SBOM Standards

The Compliance Portal generates SBOMs in two industry-standard formats:

| Format | Use Case | File |
|--------|----------|------|
| **CycloneDX 1.5** | Security scanning, vulnerability correlation, software composition analysis | `sbom/sbom.cyclonedx.json` |
| **SPDX 2.3** | License compliance, legal audits, open source governance | `sbom/sbom.spdx.json` |

Both formats are generated and published with every release, and both undergo automated vulnerability scanning.

## SBOM Generation

### Generation Process

SBOMs are automatically generated during the CI/CD pipeline using industry-standard tools:

```bash
# Install SBOM generation tools
pip install syft grype

# Generate CycloneDX SBOM
syft /path/to/compliance-portal -o cyclonedx-json=sbom/sbom.cyclonedx.json

# Generate SPDX SBOM
syft /path/to/compliance-portal -o spdx-json=sbom/sbom.spdx.json

# Scan SBOM for vulnerabilities
grype sbom:sbom/sbom.cyclonedx.json --output json > sbom/vulnerability-report.json
```

### Generation Triggers

SBOMs are regenerated:

- Every release (before publishing)
- Daily (for vulnerability tracking)
- On-demand (when dependency changes merge to `main`)

### Generation Tools

| Tool | Purpose | Version |
|------|---------|---------|
| **Syft** | SBOM generation (CycloneDX, SPDX, cyclonedx-go) | Latest |
| **Grype** | Vulnerability scanner (correlates SBOM against CVE databases) | Latest |
| **pip-audit** | Python-specific dependency vulnerability scanner | Latest |
| **Trivy** | Container image scanner (for Docker images) | Latest |

## Component Inventory

### Runtime Dependencies (25 packages)

All production dependencies included in `requirements.txt`:

| Package | Version | License | Purpose | Risk |
|---------|---------|---------|---------|------|
| **fastapi** | 0.115.4 | MIT | Web framework (HTTP, routing, OpenAPI) | Low |
| **uvicorn** | 0.27.0 | BSD-3-Clause | ASGI server (production HTTP server) | Low |
| **pydantic** | 2.6.1 | MIT | Data validation & settings management | Low |
| **sqlalchemy** | 2.0.28 | MIT | SQL ORM (database abstraction) | Low |
| **alembic** | 1.13.1 | MIT | Database schema migration tool | Low |
| **cryptography** | 42.0.5 | Apache-2.0 / BSD-3-Clause | Cryptographic operations (Ed25519, key derivation) | Critical |
| **pyjwt** | 2.8.1 | MIT | JWT encoding/decoding (authentication tokens) | High |
| **python-jose** | 3.3.0 | MIT | JOSE (JSON Web Encryption/Signature) for OIDC | High |
| **passlib** | 1.7.4 | BSD | Password hashing (PBKDF2, bcrypt) | High |
| **redis** | 5.0.1 | MIT | Redis Python client (session store) | Low |
| **aioredis** | 2.0.1 | MIT | Async Redis client | Low |
| **psycopg** | 3.1.14 | LGPL-3.0 | PostgreSQL adapter (primary database) | Medium |
| **asyncpg** | 0.28.0 | Apache-2.0 | Async PostgreSQL driver | Low |
| **httpx** | 0.25.2 | BSD | Async HTTP client (Compliance Service integration, OIDC) | Low |
| **requests** | 2.31.0 | Apache-2.0 | HTTP client (fallback, utilities) | Low |
| **weasyprint** | 68.1 | BSD-3-Clause | PDF generation with SafeUrlFetcher (SSRF protection) | Medium |
| **jinja2** | 3.1.2 | BSD-3-Clause | Template engine (HTML rendering) | Low |
| **python-dotenv** | 1.0.0 | BSD-3-Clause | Environment variable loading | Low |
| **qdrant-client** | 2.7.0 | Apache-2.0 | Vector database client (evidence similarity search) | Low |
| **tenacity** | 8.2.3 | Apache-2.0 | Retry decorator (external service resilience) | Low |
| **pydantic-settings** | 2.1.0 | MIT | Pydantic configuration management | Low |
| **python-multipart** | 0.0.6 | Apache-2.0 | Multipart form data parsing | Low |
| **email-validator** | 2.1.0 | CC0 1.0 | Email validation | Low |
| **starlette** | 0.36.3 | BSD-3-Clause | ASGI framework (FastAPI dependency) | Low |
| **typing-extensions** | 4.9.0 | PSF | Type hints (Python < 3.10 compatibility) | Low |

### Development Dependencies (15 packages)

Development-only dependencies in `requirements-dev.txt`:

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| **pytest** | 7.4.4 | MIT | Test runner (505+ tests) |
| **pytest-asyncio** | 0.23.1 | Apache-2.0 | Async test support |
| **pytest-cov** | 4.1.0 | MIT | Code coverage reporting |
| **pytest-mock** | 3.12.0 | MIT | Mocking fixtures |
| **responses** | 0.24.1 | Apache-2.0 | Mock HTTP responses |
| **faker** | 21.0.0 | MIT | Fake data generation (test fixtures) |
| **black** | 23.12.1 | MIT | Code formatter |
| **ruff** | 0.1.11 | MIT | Linter & import sorter |
| **mypy** | 1.7.1 | MIT | Static type checker |
| **bandit** | 1.7.5 | Apache-2.0 | Security linter |
| **semgrep** | 1.45.0 | LGPL-2.1 | Static analysis engine |
| **pip-audit** | 2.6.1 | MIT | Dependency vulnerability scanner |
| **locust** | 2.17.0 | MIT | Load testing framework |
| **py-spy** | 0.3.14 | Apache-2.0 | Profiler (performance analysis) |
| **hypothesis** | 6.92.1 | Mozilla Public License 2.0 | Property-based testing |

### Operating System & Runtime Dependencies

| Component | Requirement | Rationale |
|-----------|-------------|-----------|
| **Python** | 3.10, 3.11, 3.12 | Official support; security patches available for all three |
| **PostgreSQL** | 13+ | Database backend (tested: 15) |
| **Redis** | 7.0+ | Session store & cache (tested: 7-latest) |
| **Docker** | 20.10+ | Container runtime (if using containerization) |
| **Linux/macOS** | Any recent version | Development environment |

## Dependency Management

### Dependency Selection Criteria

New dependencies are evaluated against:

1. **License Compatibility**: MIT, Apache-2.0, BSD-3-Clause preferred; GPL/AGPL rejected
2. **Maintenance Health**: Active maintenance (commits in last 6 months)
3. **Security History**: No known critical/high CVEs; responsive vulnerability disclosure
4. **Code Quality**: Well-tested, documented, clear API
5. **Community Size**: Sufficient user base to catch issues
6. **Size**: Minimal dependency tree depth (transitive dependencies)

### Update Policy

| Update Type | Automation | Frequency | Review Required |
|-------------|-----------|-----------|-----------------|
| **Patch** (bug fixes) | Auto-merge if tests pass | Weekly | No |
| **Minor** (features) | Auto-PR, manual merge | Monthly | Yes (tech lead) |
| **Major** (breaking) | Manual PR required | Quarterly review | Yes (CISO + tech lead) |
| **Security patch** | Immediate hotfix | On disclosure | No (critical/high); yes (medium) |

### Pinning Strategy

- **`requirements.txt`**: All packages pinned to exact version (e.g., `fastapi==0.115.4`)
- **`requirements-dev.txt`**: Development packages pinned to exact version
- **`pyproject.toml`**: Semantic version ranges for maximum flexibility in published packages

This approach ensures reproducible builds while allowing controlled, deliberate updates.

## License Compliance

### License Summary

| License | Count | Percentage | Compliance Status |
|---------|-------|-----------|-------------------|
| **MIT** | 14 | 56% | Approved |
| **Apache-2.0** | 6 | 24% | Approved |
| **BSD-3-Clause** | 4 | 16% | Approved |
| **LGPL-3.0** | 1 | 4% | Conditional (dynamic linking only) |
| **CC0 1.0** | 1 | 4% | Approved (public domain) |
| **PSF** | 1 | 4% | Approved (Python license) |

**Total**: 25 runtime packages + 15 development packages

### License Compatibility Evaluation

#### Approved Licenses

- **MIT** (permissive): No restrictions; compatible with all other licenses
- **Apache-2.0** (permissive + patent grant): Includes patent grant; compatible with other permissive licenses
- **BSD-3-Clause** (permissive): No restrictions; compatible with all other licenses
- **ISC** (permissive): Simplified MIT; compatible with all
- **CC0 1.0** (public domain): Public domain dedication; no restrictions
- **PSF** (Python-specific): Python license; compatible with all

#### Conditional Licenses

- **LGPL-3.0** (weak copyleft): Only used in `psycopg` (PostgreSQL adapter). Requirement: must be dynamically linked (not statically), which we do. Compliance check: ✓ dynamic linking verified

#### Prohibited Licenses

- **GPL-2.0/3.0** (strong copyleft): No GPL dependencies — any derived work must also be GPL
- **AGPL-3.0** (network copyleft): No AGPL dependencies — would require source disclosure of any networked derivative
- **Proprietary/Unlicensed**: No proprietary dependencies

### Third-Party License Attribution

A full attribution document is maintained at `THIRD_PARTY_LICENSES.md` with the complete license text of all dependencies. This document is included in every release distribution.

### License Scanning in CI/CD

Every PR is checked for license compliance:

```yaml
- name: License Compliance Check
  run: |
    pip install license-checker
    license-checker --allow-only MIT Apache-2.0 BSD-2-Clause BSD-3-Clause \
                    ISC LGPL-3.0 CC0 PSF
```

## Vulnerability Tracking

### Vulnerability Scanning

Dependencies are scanned for known vulnerabilities using multiple tools:

#### pip-audit (Python-specific)

```bash
pip-audit --vulnerability db=pip-audit
```

Detects: CVEs in Python packages

#### Trivy (Container images)

```bash
trivy image compliance-portal:latest
```

Detects: OS packages (Alpine, Debian), Python packages, dependencies

#### Semgrep (Static analysis)

```bash
semgrep --config=p/security-audit portal/src/
```

Detects: Usage patterns that create vulnerabilities (even with safe dependencies)

### Vulnerability Response Timeline

| Severity | Detection | Assessment | Patch Release | Notification |
|----------|-----------|-----------|---------------|--------------|
| **Critical** (CVSS 9-10) | Continuous | < 4 hours | < 24 hours | Immediate |
| **High** (CVSS 7-8.9) | Continuous | < 8 hours | < 7 days | Within 48h |
| **Medium** (CVSS 4-6.9) | Daily | < 24 hours | < 30 days | Within 1 week |
| **Low** (CVSS 0.1-3.9) | Weekly | < 1 week | Next release | On release |

### Current Vulnerability Status

**Last Scan**: 2024-04-27 | **Scanner**: Grype + pip-audit

| Severity | Count | Status | Action |
|----------|-------|--------|--------|
| **Critical** | 0 | ✓ Clean | N/A |
| **High** | 0 | ✓ Clean | N/A |
| **Medium** | 0 | ✓ Clean | N/A |
| **Low** | 0 | ✓ Clean | N/A |

All direct and transitive dependencies are clean of known vulnerabilities as of the last scan.

## Supply Chain Security

### Dependency Provenance

All dependencies are obtained from official package registries:

| Registry | Package Types | Verification |
|----------|---------------|--------------|
| **PyPI** (pypi.org) | Python packages | Package signatures, integrity hashes |
| **GitHub** (github.com) | Source repositories | SSH key verification, commit history |
| **Docker Hub** | Container images | Image signing (Docker Content Trust) |

### Transitive Dependency Monitoring

The dependency tree is monitored for unexpected changes:

```bash
# Generate dependency tree
pip install pipdeptree
pipdeptree > deps-current.txt

# Diff against baseline
diff deps-baseline.txt deps-current.txt
```

Deep transitive dependencies are locked in `requirements.txt` to prevent surprising updates.

### Software Integrity Verification

For container images, signatures are verified on deployment:

```bash
# Verify Docker image signature
docker content trust inspect compliance-portal:latest
```

## SBOM Distribution

### Publishing

SBOMs are published with every release:

1. **GitHub Release Assets**: `sbom.cyclonedx.json`, `sbom.spdx.json`
2. **Container Registry**: Image metadata includes SBOM reference
3. **Project Website**: SBOM download link in release notes
4. **Customers**: SBOMs provided on request for compliance audits

### Machine-Readable SBOM Locations

For automation and tooling:

```
releases/
  ├── v0.1.0/
  │   ├── sbom.cyclonedx.json        # CycloneDX format
  │   ├── sbom.spdx.json              # SPDX format
  │   ├── vulnerability-report.json   # Grype scan results
  │   └── [release artifacts]
```

### Using SBOMs for Incident Response

When a CVE is published, use the SBOM to identify affected versions:

```bash
# Download latest SBOM
curl -O https://releases.example.com/v0.1.0/sbom.cyclonedx.json

# Check if component is present
grep -q "fastapi" sbom.cyclonedx.json && echo "Affected" || echo "Not affected"

# Get component version
jq '.components[] | select(.name=="fastapi") | .version' sbom.cyclonedx.json
```

### Integration with Dependency Management Tools

SBOMs can be imported into:

- **OWASP Dependency-Check**: For vulnerability correlation
- **Snyk**: For continuous monitoring and remediation
- **Dependabot**: For automated upgrade PRs
- **WhiteSource**: For license and security compliance

## Related Documents

- **DEPENDENCIES.md** — Dependency selection, approval, and maintenance procedures
- **SECURITY.md** — Vulnerability reporting and response
- **SECURITY-EOL.md** — Security patch timeline by version
- **CHANGELOG.md** — Dependencies listed per version release
- **THIRD_PARTY_LICENSES.md** — Complete license texts of all dependencies

---

**Last Updated**: 2024-04-27 | **Total Runtime Packages**: 25 | **Total Dev Packages**: 15 | **Vulnerabilities**: 0 (Critical/High/Medium) | **Next Scan**: Daily via CI/CD
