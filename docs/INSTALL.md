# Install — bulletproof-compliance-portal

This is the concise install-and-run guide. For the full production deployment
(nginx, secrets, private-network isolation) see
[`INSTALLATION.md`](INSTALLATION.md) and [`../docker/README.md`](../docker/README.md).

## Prerequisites

- **Python 3.12+** (the project targets 3.12).
- **WeasyPrint native libraries** (for PDF export):
  - macOS: `brew install cairo pango gdk-pixbuf libffi`
  - Debian/Ubuntu: `apt-get install libcairo2 libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 libffi8 shared-mime-info fonts-dejavu`
- **Optional**: Docker + Docker Compose (to run Redis, PostgreSQL, and the full
  stack), and a running **compliance service** for non-trivial workflows.

## Option A — local development (internal portal)

```bash
git clone https://github.com/bulletproofsoftware-ai/bulletproof-compliance-portal.git
cd bulletproof-compliance-portal

make install            # creates .venv and installs runtime + dev deps

cp .env.example .env    # then edit; see CONFIG.md for every variable

make test               # run the test suite (556 tests)
make run                # http://localhost:8080  (reload enabled, dev mode)
```

Then open `http://localhost:8080`. In `APP_ENV=development` the portal routes an
unauthenticated bare-URL visitor to `/auth/dev-login?role=admin` because there is
no OIDC identity provider locally — this is a development convenience only and is
never active in staging/production.

### Manual (without make)

```bash
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip wheel
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install -e .

PYTHONPATH=src .venv/bin/uvicorn portal.main:app --reload --host 0.0.0.0 --port 8080
```

The public DSR portal is the same package in `public` mode:

```bash
PYTHONPATH=src .venv/bin/uvicorn dsr_portal.main:app --reload --host 0.0.0.0 --port 8081
```

## Option B — Docker Compose (full stack)

The compose file in `docker/compose.yaml` builds both portal images and wires
Redis, PostgreSQL, nginx reverse proxies, and (optionally) the compliance
service. All published ports are bound to `127.0.0.1` by default.

```bash
cd docker
cp -r secrets.example secrets      # populate the file-mounted secrets
docker compose build
docker compose up -d
```

Default local bindings (host → container):

| Service | Host bind | Notes |
|---------|-----------|-------|
| Internal portal (via nginx) | `127.0.0.1:8453` → 8443 | TLS, private-network side |
| Public DSR portal (via nginx) | `127.0.0.1:8444` → 8444 | Internet-facing side |
| Internal app (direct) | `127.0.0.1:8001` | Behind the internal nginx |
| Public app (direct) | `127.0.0.1:8002` | Behind the public nginx |
| Redis | internal only | Session store |
| PostgreSQL | internal only | Persistence |
| Docs portal | `127.0.0.1:8095` | Optional read-only docs |

Both application images run as a **non-root** user (uid:gid `10001:10001`), use
`tini` as PID 1, and define a `/healthz` HEALTHCHECK. See
[`../docker/README.md`](../docker/README.md) for the hardening details.

## Verifying the install

```bash
# Liveness
curl -fsS http://localhost:8080/healthz

# Readiness (checks downstream dependencies)
curl -fsS http://localhost:8080/readyz

# Import check (both apps build cleanly)
PYTHONPATH=src .venv/bin/python -c "from portal.main import app; from dsr_portal.main import app as p; print('ok')"
```

## Minimum configuration

At minimum you must set (see [`CONFIG.md`](CONFIG.md) for all variables and
[`.env.example`](../.env.example) for the template):

| Variable | Meaning |
|----------|---------|
| `APP_MODE` | `internal` or `public` |
| `APP_ENV` | `development` / `staging` / `production` |
| `SESSION_SECRET` | 32-byte random string used to sign sessions/CSRF |
| `COMPLIANCE_API_BASE_URL` / `COMPLIANCE_API_TOKEN` | backing compliance service |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URI` | auth (required outside development) |
| `REDIS_URL` | session store (falls back to in-memory if unset) |
| `PG_DSN` | PostgreSQL DSN (async driver) |

## Troubleshooting

- **`weasyprint` import/render errors** — the native cairo/pango libraries are
  missing; install them (see Prerequisites). On macOS ensure the Homebrew lib
  directory is on the dynamic loader path.
- **OIDC 500 on `/` in a non-dev env** — no identity provider configured; set
  the `OIDC_*` variables or use `APP_ENV=development` for local exploration.
- **Sessions not persisting across workers** — set `REDIS_URL`; the in-memory
  store is per-process and only appropriate for single-worker development.

## Related documents

- [`INSTALLATION.md`](INSTALLATION.md) — full production install (nginx, secrets, isolation)
- [`CONFIG.md`](CONFIG.md) — every configuration variable
- [`ADMINISTRATOR.md`](ADMINISTRATOR.md) — day-2 operations
- [`../docker/README.md`](../docker/README.md) — container topology & hardening

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
