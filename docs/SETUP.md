# Development Setup Guide

This guide walks you through setting up a development environment for the Compliance Portal on your local machine.

## Prerequisites

### System Requirements

- **macOS 12+** or **Ubuntu 20.04+** or **Debian 11+** (Windows: WSL2)
- **Python 3.12** (or higher minor patch)
- **pip**, **git**
- **Docker** and **Docker Compose** (optional, for integrated stack)

### Required System Dependencies

Compliance Portal uses `weasyprint` for PDF rendering, which requires native system libraries.

**macOS (Homebrew)**:
```bash
brew install cairo pango gdk-pixbuf libffi
```

**Ubuntu/Debian (apt)**:
```bash
sudo apt-get update
sudo apt-get install -y \
  libcairo2-dev pkg-config python3-dev \
  libpango-1.0-0 libpango-cairo-1.0-0 \
  libgdk-pixbuf2.0-0 libffi-dev
```

**Alpine Linux** (Docker):
```dockerfile
RUN apk add --no-cache \
  cairo-dev pango-dev gdk-pixbuf-dev libffi-dev
```

### Verify Prerequisites

```bash
# Check Python version
python3.12 --version

# Verify pip is available
python3.12 -m pip --version

# Verify git is available
git --version

# (Optional) Check Docker
docker --version
docker compose version
```

## Step 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/<org>/compliance-portal.git
cd compliance-portal

# Verify you're on the main branch
git branch -a
```

## Step 2: Create Virtual Environment

The Makefile provides a `venv` target that uses Python 3.12:

```bash
# Create virtual environment in .venv/ (Python 3.12)
make venv

# Verify activation script exists
ls -la .venv/bin/activate
```

**Manual activation** (if not using `make`):
```bash
python3.12 -m venv .venv
source .venv/bin/activate  # macOS/Linux
# or
.venv\Scripts\activate  # Windows
```

## Step 3: Install Dependencies

All Python dependencies are pinned in `requirements.txt`:

```bash
# Install runtime + dev dependencies
make install

# Verify installation
.venv/bin/pip list | grep -E "fastapi|sqlalchemy|weasyprint"
```

**Manual installation**:
```bash
source .venv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
pip install -e .  # Install portal package in editable mode
```

## Step 4: Configure Environment

Copy the example environment file and fill in your local values:

```bash
cp .env.example .env
```

**Edit `.env`** with your local values:

```bash
# .env (local development)

# ─── App identity ────────────────────────────────────────────────────────────
APP_MODE=internal                     # Test internal portal
APP_ENV=development                   # Use dev settings
LOG_LEVEL=DEBUG                       # Verbose logging

# ─── Bind ────────────────────────────────────────────────────────────────────
INTERNAL_HOST=127.0.0.1
INTERNAL_PORT=8080

PUBLIC_HOST=127.0.0.1
PUBLIC_PORT=8081

# ─── Compliance service (WI-03) ──────────────────────────────────────────────
# For local dev, skip this (service unavailability is gracefully handled in tests)
COMPLIANCE_API_BASE_URL=https://compliance-svc.internal/api/v1/compliance
COMPLIANCE_API_TOKEN=dev-token-not-validated-locally
COMPLIANCE_API_TIMEOUT_S=10.0

# ─── OIDC (WI-02) ────────────────────────────────────────────────────────────
# For local dev, use test OIDC provider or skip enforcement
OIDC_ISSUER=https://auth.example.com/
OIDC_CLIENT_ID=local-dev
OIDC_CLIENT_SECRET=dev-secret-ignored
OIDC_REDIRECT_URI=http://localhost:8080/auth/callback
OIDC_DISCOVERY=false

# ─── Sessions ────────────────────────────────────────────────────────────────
SESSION_SECRET=dev-secret-32-bytes-minimum-1234567890abcdef
SESSION_MAX_AGE_S=3600
SESSION_COOKIE_SECURE=false             # HTTP OK for localhost
SESSION_COOKIE_HTTPONLY=true

# Redis (leave blank for in-memory store in tests)
REDIS_URL=                              # Uses in-memory fallback

# ─── PostgreSQL (read-only views — see WI-13/WI-14) ──────────────────────────
# Leave blank to skip database tests; compliance service mocking is used
PG_DSN=

# ─── Qdrant (process knowledge — WI-14) ──────────────────────────────────────
# Leave blank to skip Qdrant tests
QDRANT_URL=

# ─── Public DSR (WI-09) ──────────────────────────────────────────────────────
CAPTCHA_PROVIDER=hcaptcha
CAPTCHA_SITE_KEY=                      # Tests don't validate CAPTCHA
CAPTCHA_SECRET=
PUBLIC_RATE_LIMIT_PER_MIN=100

# ─── Markdown proxy (WI-16) ──────────────────────────────────────────────────
MARKDOWN_PROXY_URL=

# ─── Ed25519 signing (WI-12) ─────────────────────────────────────────────────
SIGNING_KEY_ID=

# ─── Trusted proxies (WI-17) ─────────────────────────────────────────────────
TRUSTED_PROXIES=127.0.0.1/32

# ─── CORS (WI-17) ────────────────────────────────────────────────────────────
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

## Step 5: Run Tests

All 505 tests pass with the default dev configuration:

```bash
# Run all tests
make test

# Expected output
# ........................................................................ [ 99%]
# .                                                                        [100%]
# 505 passed in 3.43s

# Run specific test file
pytest tests/test_auth.py -v

# Run tests with coverage
pytest tests --cov=src.portal --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
```

## Step 6: Start Development Server

The development server includes auto-reload on file changes:

```bash
# Start internal portal (port 8080)
make run

# Expected output:
# INFO:     Uvicorn running on http://127.0.0.1:8080
# INFO:     Application startup complete
```

**In another terminal**, test the health endpoint:

```bash
curl http://localhost:8080/healthz
# Expected output:
# {"status":"ok","version":"0.1.0"}
```

### Access the Portal

- **Health Check**: http://localhost:8080/healthz
- **Internal Portal** (with TLS in production): http://localhost:8080
- **Public DSR Portal**: http://localhost:8081

For production, HTTPS/TLS endpoints are configured at `https://localhost:8443` and `https://localhost:8444` (see **[INSTALLATION.md](./INSTALLATION.md)**).

## Step 7: Verify Setup

Run the complete verification suite:

```bash
# Lint (code style)
make lint
# Expected: 0 violations

# Type check (mypy)
make type
# Expected: Success: no issues found

# Test (pytest)
make test
# Expected: 505 passed

# All three
make lint && make type && make test
```

## Common Dev Tasks

### Add a New Route

```python
# src/portal/routers/new_feature.py
from fastapi import APIRouter, Depends
from portal.auth.rbac import require_role

router = APIRouter(prefix="/features", tags=["features"])

@router.get("/{feature_id}")
async def get_feature(
    feature_id: str,
    _user = Depends(require_role("officer"))
) -> dict:
    """Get a feature detail."""
    return {"feature_id": feature_id, "status": "ok"}
```

Register in `main.py`:

```python
from portal.routers import new_feature

app.include_router(new_feature.router)
```

Write tests in `tests/test_new_feature.py`:

```python
def test_get_feature_requires_officer_role(client):
    # Test that viewer role is rejected
    response = client.get("/features/123", headers={"Authorization": "Bearer viewer-token"})
    assert response.status_code == 403

def test_get_feature_success(client):
    # Test that officer role succeeds
    response = client.get("/features/123", headers={"Authorization": "Bearer officer-token"})
    assert response.status_code == 200
    assert response.json()["feature_id"] == "123"
```

### Add a Test

```python
# tests/test_my_feature.py
import pytest
from src.portal.main import create_app

def test_my_feature():
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
```

Run the test:
```bash
pytest tests/test_my_feature.py -v
```

### Add a PDF Resolver

PDF export routes (like evidence download) need custom resolvers:

```python
# src/portal/export.py
from src.shared.pdf_registry import register_pdf_resolver

@register_pdf_resolver("evidence")
async def resolve_evidence_pdf(evidence_id: str) -> bytes:
    """Render evidence PDF."""
    # Fetch from compliance service
    evidence = await compliance_client.get_evidence(evidence_id)
    
    # Render template to HTML
    html = jinja_env.get_template("evidence.html").render(evidence=evidence)
    
    # Convert to PDF (with safe URL fetcher)
    pdf = weasyprint.HTML(string=html, url_fetcher=safe_url_fetcher).write_pdf()
    
    # Watermark if needed
    pdf = apply_watermark(pdf, "AUDITOR-EVIDENCE")
    
    return pdf
```

### Run Individual Services

For local development without Docker:

```bash
# Terminal 1: Start FastAPI dev server
make run

# Terminal 2: Start Redis (if needed)
redis-server --port 6379

# Terminal 3: Start PostgreSQL (if needed)
# Assuming installed via Homebrew on macOS:
brew services start postgresql@16
```

## Troubleshooting

### `ModuleNotFoundError: No module named 'portal'`

**Solution**: Ensure you installed the package in editable mode:
```bash
source .venv/bin/activate
pip install -e .
```

### `weasyprint` fails with "No module named 'cairo'`

**Solution**: Install system dependencies:
```bash
# macOS
brew install cairo pango gdk-pixbuf libffi

# Ubuntu
sudo apt-get install libcairo2-dev
```

### Tests fail with "Redis connection refused"

**Solution**: Leave `REDIS_URL` blank in `.env`; the test suite uses in-memory fallback:
```bash
# .env
REDIS_URL=
```

### OIDC callback fails locally

**Solution**: OIDC testing is mocked in the test suite. For manual browser testing, set:
```bash
OIDC_DISCOVERY=false
OIDC_CLIENT_ID=local-dev
```

Or use the test client in pytest fixtures (see `tests/conftest.py`).

### Port 8080 already in use

**Solution**: Run on a different port:
```bash
make run -- --port 9000
# or
INTERNAL_PORT=9000 make run
```

## Next Steps

1. **Read the code**: Start with `src/portal/main.py` to understand the app factory
2. **Study patterns**: Look at `tests/test_auth.py` for OIDC + RBAC testing patterns
3. **Explore routers**: Each router in `src/portal/routers/` is self-contained; start with `health.py`
4. **Check templates**: Jinja2 templates in `src/portal/templates/` show the HTMX UI patterns
5. **Review specs**: All 19 work items are documented in `docs/COMPLETE/WI-*.md`

## Running with Docker Compose (Optional)

For a complete local stack with PostgreSQL, Redis, and Qdrant:

```bash
# Start all services
docker compose -f docker-compose.dev.yml up

# In .env, configure to use Docker services
REDIS_URL=redis://localhost:6379/0
PG_DSN=postgresql+asyncpg://portal:portal@localhost:5432/compliance_portal
QDRANT_URL=http://localhost:6333

# Run tests
make test

# Stop all services
docker compose -f docker-compose.dev.yml down
```

See **[docker/README.md](../docker/README.md)** for detailed Docker setup instructions.
