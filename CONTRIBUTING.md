# Contributing to Compliance Portal

Thank you for your interest in contributing to Compliance Portal! We welcome contributions from developers, security researchers, documentation writers, and community members.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Workflow](#development-workflow)
4. [Code Standards](#code-standards)
5. [Testing Requirements](#testing-requirements)
6. [Documentation](#documentation)
7. [Submitting Changes](#submitting-changes)
8. [Review Process](#review-process)
9. [Security Vulnerabilities](#security-vulnerabilities)

## Code of Conduct

We are committed to providing a welcoming, inclusive, and professional environment for all contributors. Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating. All contributors are expected to uphold these standards.

**Enforcement**: Violations should be reported to conduct@acme.com with details of the incident. We take all reports seriously and will investigate promptly.

## Getting Started

### Prerequisites

- Python 3.10+
- Docker & Docker Compose (for containerized development)
- Git
- PostgreSQL 14+ (or use Docker)
- Node.js 18+ (for frontend build tools, if needed)

### Setup for Development

1. **Fork and clone the repository**:
   ```bash
   git clone https://github.com/[org]/compliance-portal.git
   cd compliance-portal
   git remote add upstream https://github.com/[org]/compliance-portal.git
   ```

2. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Follow the development setup guide**:
   ```bash
   see docs/SETUP.md for detailed instructions
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

5. **Run the application**:
   ```bash
   python main.py
   # Application starts on https://localhost:8443
   ```

6. **Run tests to verify your setup**:
   ```bash
   pytest
   # Should pass all 505+ tests
   ```

## Development Workflow

### Branch Naming Convention

Use clear, descriptive branch names:

- `feature/description` — New features
- `fix/description` — Bug fixes
- `docs/description` — Documentation updates
- `refactor/description` — Code refactoring
- `test/description` — Test improvements
- `security/description` — Security fixes

Example: `feature/audit-export-pdf`, `fix/session-timeout-issue`, `docs/architecture-update`

### Commit Message Format

Write clear, concise commit messages that explain the "why" not just the "what":

```
<type>: <subject>

<body>

<footer>
```

**Format**:
- Type: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `security`, `chore`
- Subject: 50 characters or less, imperative mood ("add" not "added")
- Body: Detailed explanation (wrap at 72 characters)
- Footer: Breaking changes, issue references

**Example**:
```
feat: add PDF encryption for sensitive audit exports

Add AES-256 encryption for audit PDF exports containing PII.
Encryption key is derived from user's session token and audit ID,
making exports secure when shared via email or stored on disk.

Implements REQ-CPL-045: Encryption of sensitive exports
Fixes #1234
```

### Keep Commits Atomic

- One logical change per commit
- Commits should be self-contained and build successfully
- Tests should pass for each commit

### Sync with Upstream

Regularly sync your branch with upstream main:

```bash
git fetch upstream
git rebase upstream/main
```

## Code Standards

### Python Code Style

We follow [PEP 8](https://pep8.org/) with additional standards:

- **Line length**: 100 characters max
- **Imports**: Organized (stdlib → third-party → local)
- **Type hints**: All functions must have type hints
- **Docstrings**: All modules, classes, and public functions must have docstrings

**Docstring Format** (Google style):

```python
def create_audit(audit_data: dict[str, Any]) -> Audit:
    """Create a new audit record in the database.
    
    Args:
        audit_data: Dictionary containing audit fields (name, scope, etc).
            Must include 'name', 'scope', and 'created_by' keys.
    
    Returns:
        Audit: The newly created audit object with ID assigned.
    
    Raises:
        ValueError: If required fields are missing or invalid.
        DatabaseError: If database write fails.
    
    Example:
        >>> audit = create_audit({"name": "Q4 2024", "scope": "all"})
        >>> print(audit.id)
        "aud-12345"
    """
```

### Security Standards

All contributions must follow security best practices:

- **Input validation**: Validate all user inputs
- **SQL injection prevention**: Use parameterized queries (SQLAlchemy ORM)
- **Authentication**: Verify OIDC token validity
- **Authorization**: Check user roles and permissions
- **Logging**: Log security events (logins, permission changes, failed actions)
- **Error handling**: Don't expose sensitive information in error messages
- **No hardcoded secrets**: All secrets must come from environment variables
- **Dependencies**: No unvetted or outdated dependencies

See [Security Policy](SECURITY.md) for vulnerability reporting.

### FastAPI Router Standards

```python
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Annotated

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])

@router.get("/", response_model=list[AuditResponse])
async def list_audits(
    current_user: Annotated[User, Depends(get_current_user)],
    skip: int = 0,
    limit: int = 100
) -> list[AuditResponse]:
    """List audits accessible by current user.
    
    Requires: authenticated user with 'auditor' or 'admin' role.
    """
    if not user_has_role(current_user, ["auditor", "admin"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    # Implementation
```

### Template Standards

HTML templates must:
- Use semantic HTML5
- Include ARIA labels for accessibility
- Have proper CSP headers
- Escape all user input (`{{ variable | escape }}`)
- Use template inheritance (extend `base.html`)

```html
{% extends "base.html" %}

{% block title %}Audit Details - Compliance Portal{% endblock %}

{% block content %}
<main id="main-content" role="main">
    <h1>{{ audit.name | escape }}</h1>
    <!-- Content -->
</main>
{% endblock %}
```

## Testing Requirements

### Test Coverage Minimum

- **Unit tests**: 80% minimum coverage (required)
- **Integration tests**: All major workflows
- **End-to-end tests**: Critical user paths

### Writing Tests

1. **Arrange-Act-Assert pattern**:
   ```python
   def test_audit_creation():
       # Arrange: Set up test data
       audit_input = {"name": "Q4 2024", "scope": "all"}
       
       # Act: Perform the action
       result = create_audit(audit_input)
       
       # Assert: Verify the result
       assert result.id is not None
       assert result.name == "Q4 2024"
   ```

2. **Use fixtures for reusable setup**:
   ```python
   @pytest.fixture
   def sample_audit():
       return Audit(name="Test", scope="all", created_by="test_user")
   
   def test_audit_export(sample_audit):
       result = export_audit_pdf(sample_audit)
       assert result is not None
   ```

3. **Test both happy path and error cases**:
   ```python
   def test_create_audit_with_invalid_data():
       with pytest.raises(ValueError):
           create_audit({})  # Missing required fields
   ```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_audit.py

# Run with coverage report
pytest --cov=portal --cov-report=html

# Run specific test
pytest tests/test_audit.py::test_audit_creation
```

### Coverage Requirements

- Run `pytest --cov=portal` before submitting PR
- Target 80%+ coverage
- New code must have 90%+ coverage
- Mark with `# pragma: no cover` if skipping specific lines is justified

## Documentation

### Update Documentation For:
- New features (update README.md and relevant guide)
- Configuration changes (update CONFIG.md)
- API changes (update docs/API.md)
- Setup changes (update docs/SETUP.md)
- Architecture changes (update docs/ARCHITECTURE.md)

### Documentation Format

- Use Markdown with proper heading hierarchy
- Include code examples for features
- Add cross-references to related docs
- Update the table of contents if adding new sections

### Changelog Entry

Update `CHANGELOG.md` with your change:

```markdown
## [Unreleased]

### Added
- New feature description

### Fixed
- Bug fix description

### Changed
- Change description
```

## Submitting Changes

### Before Submitting Your PR

1. **Verify your changes compile and test**:
   ```bash
   pytest -xvs
   pytest --cov=portal
   ```

2. **Check code quality**:
   ```bash
   pylint portal
   flake8 portal
   black --check portal
   ```

3. **Verify security**:
   ```bash
   bandit -r portal
   ```

4. **Update documentation**:
   - Docstrings for new functions
   - README.md if affecting user experience
   - docs/ if affecting operations or setup

5. **Add tests**:
   - Unit tests for new code
   - Integration tests for workflows
   - At least 80% coverage required

6. **Sync with upstream**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Create a Pull Request

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create PR on GitHub**: https://github.com/[org]/compliance-portal/pulls

3. **Fill in the PR template**:
   - **Description**: What does this PR do?
   - **Related Issue**: Fixes #123
   - **Type of Change**: Feature/Fix/Docs/Security
   - **Testing**: How was this tested?
   - **Checklist**: Mark items as complete

### PR Title and Description

**Title**: Brief, clear description (50 chars)
- `add: PDF encryption for audit exports`
- `fix: session timeout race condition`
- `docs: update architecture diagram`

**Description**: Detailed explanation
```markdown
## What does this PR do?
Explains the change and why it's needed.

## Related issues
Fixes #1234

## Testing
How was this tested? Include test names or output.

## Screenshots (if UI changes)
Before/after screenshots showing the change.
```

## Review Process

### What to Expect

1. **Automated checks** (required):
   - Tests must pass (100% required)
   - Code coverage must not decrease
   - No security vulnerabilities detected
   - Code style checks must pass

2. **Code review** (1-2 reviewers):
   - At least one maintainer review required
   - For security changes: both maintainer and security review
   - For architecture changes: architect review required
   - For documentation: technical writer review

3. **Approval & Merge**:
   - All reviews must approve
   - All CI checks must pass
   - PR is squashed and merged to main
   - Branch is deleted

### Responding to Review Comments

- Address all comments or explain your reasoning
- Mark conversations as resolved only after addressing
- Push follow-up commits (don't force push)
- Request re-review when changes are complete

### Timelines

| PR Type | Target Review Time |
|---------|-------------------|
| Documentation | 24 hours |
| Bug fix | 48 hours |
| Feature | 3-5 days |
| Security | 24 hours |

## Security Vulnerabilities

### Responsible Disclosure

**DO NOT** report security vulnerabilities in public GitHub issues.

For security issues:
1. Email: security@acme.com
2. Include vulnerability description and proof-of-concept
3. Do not disclose publicly until we've had time to fix

See [Security Policy](SECURITY.md) for full details.

### Security Review Checklist

Before submitting a PR that touches security:

- [ ] No hardcoded secrets or credentials
- [ ] Input validation on all user inputs
- [ ] Proper authentication checks
- [ ] Authorization checks for all operations
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (template escaping)
- [ ] CSRF protection (if state-changing)
- [ ] No sensitive data in error messages
- [ ] Audit logging for sensitive operations
- [ ] Security tests included

## Additional Resources

- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Setup Guide](docs/SETUP.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Issue Tracker](https://github.com/[org]/compliance-portal/issues)
- [Discussions](https://github.com/[org]/compliance-portal/discussions)

## Questions?

- **GitHub Discussions**: https://github.com/[org]/compliance-portal/discussions
- **Issues**: https://github.com/[org]/compliance-portal/issues
- **Email**: support@acme.com

---

Thank you for contributing to Compliance Portal! Your efforts help make our project better and more secure.
