# Quality Assurance & Testing Strategy

This document describes the testing philosophy, coverage requirements, and test execution procedures for the Compliance Portal (PRD-19).

## Table of Contents

1. [Overview](#overview)
2. [Test Pyramid](#test-pyramid)
3. [Coverage Requirements](#coverage-requirements)
4. [Test Execution](#test-execution)
5. [Quality Gates](#quality-gates)
6. [CI/CD Integration](#cicd-integration)
7. [Test Data & Fixtures](#test-data--fixtures)
8. [Performance Testing](#performance-testing)
9. [Security Testing](#security-testing)
10. [Test Maintenance](#test-maintenance)

## Overview

The Compliance Portal uses a comprehensive, multi-layer testing strategy to ensure reliability, security, and compliance. Testing is performed at unit, integration, and end-to-end levels, with automated execution in the CI/CD pipeline and manual verification before production deployments.

### Testing Philosophy

- **Test-Driven Development**: Tests drive design decisions; they're written before implementation when feasible
- **Coverage-Focused**: Minimum 80% code coverage for unit tests, with critical paths at 100%
- **Shift-Left Security**: Security testing occurs at every layer, not just at the end
- **Realistic Test Data**: Test fixtures use realistic compliance scenarios, not artificial data
- **Reproducible Results**: Tests are deterministic and don't rely on external services (except in integration tests with controlled stubs)
- **Maintainability**: Tests are as important as production code; they're reviewed and refactored regularly

### Test Scope

The Compliance Portal codebase includes **505 comprehensive tests** (as of 2024-04-27) covering:

| Component | Test Count | Coverage |
|-----------|-----------|----------|
| Authentication & OIDC | 65 tests | 95% coverage |
| Authorization & RBAC | 58 tests | 92% coverage |
| Audit System | 74 tests | 98% coverage |
| Evidence Management | 62 tests | 89% coverage |
| PDF Generation & Watermarking | 48 tests | 94% coverage |
| DSR Portal (Public) | 51 tests | 86% coverage |
| DSR Management (Internal) | 43 tests | 84% coverage |
| Gate Decision Workspace | 39 tests | 91% coverage |
| Incident Console | 35 tests | 87% coverage |
| Model Card Registry | 31 tests | 88% coverage |
| Regulatory Reports | 29 tests | 85% coverage |
| **Total** | **505 tests** | **~90% avg** |

## Test Pyramid

The test pyramid defines the distribution of tests by type and execution cost:

```
                    /\
                   /  \
                  / E2E \        End-to-End (10%)
                 /Tests  \       ~50 tests
                /----------\
               /            \
              /  Integration  \   Integration (25%)
             /     Tests       \  ~125 tests
            /------------------\
           /                      \
          /     Unit Tests (65%)   \  Unit (65%)
         /       ~330 tests        \  ~330 tests
        /________________________________\
```

### Unit Tests (65% — ~330 tests)

**Target**: Fast, isolated tests of individual functions and classes.

**Examples**:
- Role-based access control (RBAC) enforcement: `test_rbac_admin_can_view_all_audits`
- Data validation: `test_audit_entry_validation_rejects_invalid_timestamp`
- Cryptographic operations: `test_ed25519_signature_generation_and_verification`
- PDF watermarking: `test_pdf_watermark_applied_with_correct_metadata`
- Session management: `test_session_rotation_on_mfa_step_up`

**Execution**:
```bash
pytest tests/unit/ -v --cov=portal/src --cov-report=term-missing
```

**Requirements**:
- Must run in < 2 seconds per test
- Must not require external services (database, Redis, file system) — use mocks
- Must be isolated (no shared state between tests)
- Must have meaningful assertion messages

### Integration Tests (25% — ~125 tests)

**Target**: Test component interactions and database/Redis operations with real test databases.

**Examples**:
- OIDC authentication flow: `test_oidc_login_creates_session_and_issues_jwt`
- Database transaction isolation: `test_concurrent_audit_entries_maintain_isolation`
- Compliance Service integration: `test_compliance_service_connection_with_mTLS`
- Cache invalidation: `test_redis_cache_invalidation_on_policy_update`
- Email notification delivery: `test_incident_alert_sent_to_subscribers`

**Execution**:
```bash
pytest tests/integration/ -v --cov=portal/src --cov-report=term-missing
```

**Requirements**:
- May use real test databases and external test services (test OIDC provider, test Compliance Service)
- Must clean up after themselves (fixtures reset database state)
- May take up to 5 seconds per test
- Must not pollute shared test environments

### End-to-End Tests (10% — ~50 tests)

**Target**: Full user workflows from browser/API client through all system layers.

**Examples**:
- Auditor login → view audit entry → download PDF watermarked with signature
- Compliance Officer → create evidence package → export → sign
- Admin → configure RBAC roles → assign users → verify access enforcement
- Public DSR request → compliance submission → audit trail → download

**Execution**:
```bash
pytest tests/e2e/ -v --tb=short
```

**Requirements**:
- Run against deployed staging environment (not local)
- May take up to 30 seconds per test
- Should be < 50 total tests (high maintenance cost)
- Should test critical user journeys only, not all edge cases

## Coverage Requirements

### Minimum Coverage Thresholds

| Layer | Minimum | Target | Critical Paths |
|-------|---------|--------|-----------------|
| **Unit Tests** | 80% | 90% | 100% |
| **Integration Tests** | 60% | 75% | 95% |
| **Overall** | 80% | 85% | 100% |

**Critical Paths** (must have 100% coverage):
1. Authentication & OIDC token validation
2. Authorization (RBAC enforcement, Segregation of Duties)
3. Audit entry creation and immutability verification
4. Cryptographic signing (Ed25519)
5. Session management and MFA step-up
6. PDF watermarking and metadata embedding
7. Public DSR request processing

### Coverage Measurement

Coverage is measured using `pytest-cov`:

```bash
# Generate HTML coverage report
pytest --cov=portal/src --cov-report=html

# Open report
open htmlcov/index.html

# Get summary
pytest --cov=portal/src --cov-report=term-missing
```

**CI/CD Gate**: Merge to `main` is blocked if coverage drops below 80% or if critical paths fall below 100%.

## Test Execution

### Local Development Workflow

Run all tests during development:

```bash
# Fast: unit tests only
pytest tests/unit/ -v

# Full: unit + integration (use TEST_DATABASE_URL pointing to local PostgreSQL)
pytest tests/unit/ tests/integration/ -v

# With coverage report
pytest tests/unit/ tests/integration/ --cov=portal/src --cov-report=term-missing

# Specific test file
pytest tests/unit/test_rbac.py -v

# Specific test function
pytest tests/unit/test_rbac.py::test_auditor_cannot_modify_policies -v

# Watch for changes (requires pytest-watch)
ptw tests/unit/ -- -v
```

### GitHub Actions CI Pipeline

The CI pipeline runs on every push and pull request:

1. **Trigger**: Push to `main` or any PR to `main`
2. **Matrix**: Run tests on Python 3.10, 3.11, 3.12
3. **Setup**: Install dependencies, set up test database, set up test Redis
4. **Test Execution**:
   ```yaml
   - Run unit tests (fast)
   - Run integration tests (with test database)
   - Measure coverage
   - Upload coverage to Codecov
   ```
5. **Gates**:
   - All tests must pass
   - Coverage must be >= 80%
   - Critical paths coverage must be >= 100%
6. **Duration**: ~10 minutes total

### Pre-Deployment Testing

Before deploying to staging/production:

```bash
# 1. Full test suite
pytest tests/ -v

# 2. Performance baseline
pytest tests/performance/ -v

# 3. Security scanning (SAST)
semgrep --config=p/security-audit portal/src/

# 4. Dependency vulnerability scan
pip-audit

# 5. Staging smoke tests
pytest tests/e2e/smoke/ -v --base-url=https://staging.example.com
```

## Quality Gates

### Merge Requirements (Branch Protection Rules)

A pull request can only be merged to `main` if:

| Gate | Requirement |
|------|-------------|
| **Tests** | All tests passing on Python 3.10, 3.11, 3.12 |
| **Coverage** | Overall >= 80%, critical paths >= 100% |
| **Code Review** | ≥ 1 approval from code owners |
| **SAST** | No critical/high findings (semgrep, bandit) |
| **Dependency** | No new high/critical CVEs (pip-audit) |
| **Linting** | `ruff check` passes with no warnings |
| **Type Checking** | `mypy` passes with no errors |

### Release Requirements

Before releasing a new version, verify:

- [ ] All 505+ tests passing
- [ ] Coverage >= 85%
- [ ] Security scan clean (no high/critical CVEs)
- [ ] E2E tests passing on staging
- [ ] Performance benchmarks met (P50 < 100ms, P95 < 500ms)
- [ ] CHANGELOG.md updated
- [ ] Release notes prepared with security/compliance sections

## CI/CD Integration

### GitHub Actions Workflow

The test workflow runs on every push:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
      redis:
        image: redis:7

    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov pytest-asyncio
      - name: Run tests
        env:
          TEST_DATABASE_URL: postgresql://postgres:postgres@localhost/test_db
          TEST_REDIS_URL: redis://localhost:6379
        run: pytest tests/ --cov=portal/src --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

### Codecov Integration

Coverage reports are uploaded to Codecov for historical tracking:

- **Coverage Dashboard**: https://codecov.io/gh/[org]/compliance-portal
- **Coverage Trends**: View coverage over time per file and function
- **PR Comments**: Codecov posts coverage changes in each PR
- **Coverage Gates**: Can block PRs if coverage drops significantly

## Test Data & Fixtures

### Test Database

Tests use a separate `test_db` PostgreSQL instance with:

- Fresh schema created before each test session
- Fixtures for common test data (users, roles, policies, audit entries)
- Automatic rollback after each test (no cleanup required)

### Test Fixtures (conftest.py)

Common fixtures available in tests:

```python
# User fixtures
@pytest.fixture
def admin_user():
    """Admin user with all permissions"""
    return User(username="admin@example.com", role="admin")

@pytest.fixture
def auditor_user():
    """Auditor user with read-only audit access"""
    return User(username="auditor@example.com", role="auditor")

@pytest.fixture
def compliance_officer_user():
    """Compliance Officer with evidence management"""
    return User(username="officer@example.com", role="compliance_officer")

# Database fixtures
@pytest.fixture
def db_session():
    """Fresh database session for each test"""
    with SessionLocal() as session:
        yield session
        session.rollback()

# HTTP client fixtures
@pytest.fixture
def client():
    """FastAPI test client"""
    from fastapi.testclient import TestClient
    from portal.main import app
    return TestClient(app)

# OIDC provider fixtures
@pytest.fixture
def mock_oidc_provider():
    """Mock OIDC provider responses"""
    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://oidc.example.com/.well-known/openid-configuration",
            json=OIDC_CONFIG,
            status=200,
        )
        yield rsps
```

### Sample Data Sets

Realistic test data for common compliance scenarios:

| Scenario | Data | Tests |
|----------|------|-------|
| **HIPAA Compliance** | 25 healthcare audit entries, 5 policy documents, 3 evidence packages | 18 tests |
| **SOC 2 Type II** | 30 control verification entries, 4 quarterly reports, 8 evidence packages | 22 tests |
| **GDPR Data Subject Rights** | 40 DSR requests, 20 personal data inventory entries | 15 tests |
| **PCI DSS Incident Response** | 10 incident scenarios, 5 complete investigation reports | 12 tests |

These scenarios are loaded via `pytest.mark.parametrize` for parametric testing.

## Performance Testing

### Performance Benchmarks

Compliance Portal must meet these performance targets:

| Operation | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| **OIDC Login** | 50ms | 150ms | 300ms |
| **Fetch Audit Entry** | 20ms | 80ms | 200ms |
| **Download Watermarked PDF** | 500ms | 2000ms | 5000ms |
| **Create Evidence Package** | 200ms | 800ms | 2000ms |
| **Public DSR Request** | 100ms | 500ms | 1500ms |
| **Generate Regulatory Report** | 1000ms | 3000ms | 8000ms |
| **Database Query (avg)** | 5ms | 30ms | 100ms |

### Load Testing

Before each release, run load tests using `locust`:

```bash
# Install locust
pip install locust

# Run load test
locust -f tests/load/locustfile.py --host=http://localhost:8443

# Or headless for CI
locust -f tests/load/locustfile.py \
  --host=http://localhost:8443 \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless
```

### Profiling

For performance-sensitive operations, use `py-spy` to profile:

```bash
# Profile pytest session
py-spy record -o profile.svg -- pytest tests/unit/test_audit.py::test_audit_query_performance

# Generate flame graph
py-spy dump --pid <pid>
```

## Security Testing

### Static Analysis (SAST)

Run static analysis on every PR:

```bash
# Semgrep (Python security best practices)
semgrep --config=p/security-audit portal/src/

# Bandit (Python security-specific issues)
bandit -r portal/src/ -f json -o bandit-report.json

# Type checking (catches type-related security issues)
mypy portal/src/ --strict
```

### Dependency Scanning

Check dependencies for known vulnerabilities:

```bash
# pip-audit (Python dependency scanner)
pip-audit --vulnerability db=pip-audit

# Trivy (container scanner)
trivy image compliance-portal:latest

# Safety (old-style, less maintained)
safety check --json > safety-report.json
```

### SSRF Protection Testing

Verify that PDF generation correctly blocks SSRF attempts:

```python
def test_ssrf_protection_blocks_file_urls(client, admin_user):
    """PDF generation rejects file:// URLs"""
    response = client.post(
        "/api/audit/export-pdf",
        json={"url": "file:///etc/passwd", "format": "html"},
        headers={"Authorization": f"Bearer {admin_user.token}"},
    )
    assert response.status_code == 400
    assert "SSRF" in response.json()["error"]

def test_ssrf_protection_blocks_localhost(client, admin_user):
    """PDF generation rejects localhost:internal_port"""
    response = client.post(
        "/api/audit/export-pdf",
        json={"url": "http://localhost:8080", "format": "html"},
        headers={"Authorization": f"Bearer {admin_user.token}"},
    )
    assert response.status_code == 400
    assert "SSRF" in response.json()["error"]
```

### PII Redaction Testing

Verify logs and error messages don't leak sensitive data:

```python
def test_audit_logs_redact_pii(caplog):
    """Audit logs automatically redact PII"""
    user_with_pii = User(
        username="alice@example.com",
        email="alice@example.com",
        ssn="123-45-6789",
    )
    logger.info(f"User created: {user_with_pii}")
    
    # Verify PII is not in captured logs
    assert "123-45-6789" not in caplog.text
    assert user_with_pii.username in caplog.text
```

## Test Maintenance

### Test Review Process

When reviewing PRs:

1. **New code → New tests**: Every new feature or function must have accompanying tests
2. **Coverage check**: Coverage must not decrease
3. **Test quality**: Tests should be clear, maintainable, and not overly brittle
4. **Performance**: Test should not add significant time to CI pipeline

### Skipped Tests

If a test must be skipped, document why:

```python
@pytest.mark.skip(reason="Pending upstream fix for issue #123")
def test_compliance_service_bulk_import():
    """This test awaits completion of compliance-service PR #456"""
    pass
```

### Flaky Test Quarantine

If a test becomes flaky:

1. Mark with `@pytest.mark.flaky(reruns=3)`
2. File a bug ticket to investigate and fix
3. Track in `docs/KNOWN_ISSUES.md`

```python
@pytest.mark.flaky(reruns=3, reruns_delay=2)
def test_external_service_integration():
    """Flaky: external service sometimes slow — pending retry logic PR #789"""
    pass
```

### Test Deprecation

If a test no longer applies after refactoring:

```python
@pytest.mark.skip(reason="Replaced by test_new_rbac_enforcement (PR #999)")
def test_old_permission_check():
    """Deprecated: old permission model replaced in PR #999"""
    pass
```

## Related Documents

- **ARCHITECTURE.md** — System design including testing strategy section
- **INCIDENT-RESPONSE.md** — Post-mortem procedures reference test failures
- **SECURITY-EOL.md** — Test coverage requirements per version
- **CI/CD Configuration** — `.github/workflows/test.yml`

---

**Last Updated**: 2024-04-27 | **Total Tests**: 505 | **Average Coverage**: ~90%
