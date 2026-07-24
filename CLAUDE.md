# CLAUDE.md — Compliance Portal

## What This Is

PRD-19: Compliance Portal & Human-in-the-Loop Interface. FastAPI + HTMX + D3.js + Chart.js web application providing compliance officers, external auditors, data subjects, and domain experts with secure access to the platform's regulatory compliance engine.

## Tech Stack

- **Backend**: Python 3.12+, FastAPI, uvicorn
- **Frontend**: HTMX (server-rendered partials), D3.js, Chart.js
- **Database**: PostgreSQL (reads from PRD-18 compliance tables), Qdrant (process knowledge, metrics)
- **Auth**: OIDC (Authentik IdP), 5 roles: admin, compliance_officer, auditor, sme, viewer
- **Deployment**: Docker Compose on localhost, two containers (internal portal + public DSR portal)

## Architecture Constraints

- Portal calls compliance service REST API exclusively — zero business logic in portal layer
- Read-heavy with narrow write paths (gate decisions, DSR resolution, incident notes, knowledge verification, model card reviews)
- Public DSR portal is architecturally separate: isolated container, separate domain, rate-limited, WAF-protected
- No portal endpoint writes to immutable_audit_events directly

## Project Structure

```
src/                    Application source
  portal/               Internal portal (FastAPI app)
  dsr_portal/           Public DSR portal (separate FastAPI app)
  shared/               Shared utilities (auth, RBAC, API client)
tests/                  Test suite
docker/                 Docker Compose and Dockerfiles
docs/                   Documentation (install, config, API, architecture)
```

## Commands

```bash
# Development
docker compose -f docker/compose.yaml up -d           # Start all services
docker compose -f docker/compose.yaml logs -f portal  # Follow portal logs
PYTHONPATH=src pytest -q                              # Run tests

# Linting
ruff check src/
mypy src/
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the development workflow, coding
standards, and review expectations. All changes must keep the test suite green
(`PYTHONPATH=src pytest -q`) and pass `ruff check src/` and `mypy src/`.
