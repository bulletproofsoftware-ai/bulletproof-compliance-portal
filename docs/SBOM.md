# Software Bill of Materials (SBOM)

This document inventories the third-party components that ship in the compliance
portal, with pinned versions and licenses. It is generated from the repository's
real dependency manifests — `requirements.txt` and `pyproject.toml` — not from a
template.

A machine-readable **CycloneDX 1.6** SBOM of the production dependency set —
including transitive packages — is committed alongside this document at
[`compliance-portal.cyclonedx.json`](compliance-portal.cyclonedx.json).

## How the SBOM is generated

```bash
# Build a production-only environment (no dev/test tooling), then inventory it.
# Generating from the RESOLVED environment rather than the manifest is what
# captures transitive packages and license metadata — `cyclonedx-py requirements`
# reads only the direct pins and yields no licenses.
python3.12 -m venv .venv-sbom
grep -vE '^(pytest|pytest-asyncio|pytest-cov|ruff|mypy|respx|freezegun|fakeredis)' \
  requirements.txt > /tmp/prod-req.txt
.venv-sbom/bin/pip install -r /tmp/prod-req.txt
.venv-sbom/bin/pip install cyclonedx-bom
.venv-sbom/bin/cyclonedx-py environment .venv-sbom \
  --output-format JSON --output-reproducible \
  -o docs/compliance-portal.cyclonedx.json
```

The committed CycloneDX file contains **94 components** — the 26 direct runtime
dependencies pinned in `requirements.txt` plus their transitive closure.
Development and test tooling (`pytest`, `ruff`, `mypy`, `respx`, `freezegun`,
`fakeredis`) is intentionally excluded from the production SBOM but listed in the
Development dependencies table below for completeness.

> [!warning] Known gap — no component hashes
> `requirements.txt` is not hash-pinned, so component hashes cannot be derived
> and are absent from the CycloneDX file. CISA 2025 SBOM minimum elements are
> therefore only partially met. Closing this requires a hash-pinned lockfile
> (`pip-compile --generate-hashes`).

Vulnerability posture for these components is tracked continuously by the Code
Hardener scan; the latest result (**0 critical / 0 high**) is in
[`scan/scan-report.md`](scan/scan-report.md).

## Runtime dependencies (26 direct)

Direct production dependencies, exactly as pinned in `requirements.txt`. Versions
and licenses are read from the installed distribution metadata.

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| fastapi | 0.140.0 | MIT | Web framework (HTTP, routing, OpenAPI) |
| uvicorn[standard] | 0.32.0 | BSD-3-Clause | ASGI server |
| starlette | 1.3.1 | BSD-3-Clause | ASGI toolkit underlying FastAPI |
| jinja2 | 3.1.6 | BSD-3-Clause | HTML template engine |
| pydantic | 2.9.2 | MIT | Data validation & models |
| pydantic-settings | 2.6.1 | MIT | Typed settings from env |
| httpx | 0.27.2 | BSD-3-Clause | Async HTTP client (compliance service, OIDC) |
| python-multipart | 0.0.31 | Apache-2.0 | Multipart form parsing |
| structlog | 24.4.0 | MIT / Apache-2.0 | Structured logging |
| orjson | 3.11.9 | Apache-2.0 / MIT | Fast JSON serialization |
| asyncpg | 0.30.0 | Apache-2.0 | Async PostgreSQL driver |
| sqlalchemy | 2.0.36 | MIT | SQL toolkit / ORM |
| alembic | 1.13.3 | MIT | Database migrations |
| authlib | 1.7.2 | BSD-3-Clause | OAuth/OIDC client (auth flows) |
| itsdangerous | 2.2.0 | BSD-3-Clause | Signed tokens/cookies |
| cryptography | 49.0.0 | Apache-2.0 / BSD-3-Clause | Cryptographic primitives (Ed25519, KDFs) |
| redis | 5.2.0 | MIT | Redis client (session store) |
| slowapi | 0.1.9 | MIT | Rate limiting |
| prometheus-client | 0.21.0 | Apache-2.0 | Metrics exposition (`/metrics`) |
| weasyprint | 69.0 | BSD-3-Clause | PDF rendering (evidence/report export) |
| pikepdf | 10.5.1 | MPL-2.0 | PDF manipulation |
| pyHanko | 0.34.1 | MIT | PDF digital signatures |
| Brotli | 1.2.0 | MIT | Brotli compression |
| cachetools | 7.0.6 | MIT | In-process caches |
| markdown-it-py | 3.0.0 | MIT | Markdown rendering (incident notes) |
| bleach | 6.4.0 | Apache-2.0 | HTML sanitisation |

## Development dependencies (8, not in the production SBOM)

Pinned in `requirements.txt` for reproducible CI and mirrored in the `dev` extra
of `pyproject.toml`.

| Package | Version | License | Purpose |
|---------|---------|---------|---------|
| pytest | 9.0.3 | MIT | Test runner |
| pytest-asyncio | 1.4.0 | Apache-2.0 | Async test support |
| pytest-cov | 6.0.0 | MIT | Coverage reporting |
| ruff | 0.7.4 | MIT | Linter / formatter |
| mypy | 1.13.0 | MIT | Static type checker |
| respx | 0.21.1 | BSD-3-Clause | HTTPX mock transport |
| freezegun | 1.5.1 | Apache-2.0 | Time freezing in tests |
| fakeredis | 2.26.1 | BSD-3-Clause | In-memory Redis for tests |

## Base and runtime images

The portal images and their backing services are built on the following pinned
base images (from `docker/Dockerfile.*` and `docker/compose.yaml`):

| Image | Base | Used by |
|-------|------|---------|
| `compliance-portal-internal` | `python:3.12-slim` | Internal portal (multi-stage build) |
| `compliance-portal-public` | `python:3.12-slim` | Public DSR portal (multi-stage build) |
| Reverse proxy | `nginx:1.27-alpine` | TLS termination for both portals |
| Session store | `redis:7.4-alpine` | Sessions and rate-limit counters |
| Database | `postgres:16-alpine` | Application persistence |

Both application images run as a non-root user (uid:gid `10001:10001`, no login
shell), use `tini` as PID 1, and expose a `/healthz` HEALTHCHECK. See
[`../docker/README.md`](../docker/README.md).

## License summary

All runtime dependencies use permissive licenses (MIT, BSD-3-Clause, Apache-2.0)
or weak-copyleft MPL-2.0 (`pikepdf`, used unmodified as a library). No GPL/AGPL
runtime dependencies are present. Full license texts are in
[`../THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md).

| License family | Notes |
|----------------|-------|
| MIT | Permissive; no obligations beyond attribution |
| BSD-3-Clause | Permissive; attribution + no-endorsement |
| Apache-2.0 | Permissive + explicit patent grant |
| MPL-2.0 | File-level weak copyleft; satisfied by unmodified library use |

## Regenerating and verifying

```bash
# Regenerate the production SBOM after changing requirements.txt
# (see "How the SBOM is generated" above — generate from a resolved venv,
#  not from the manifest, or you lose transitives and licenses)

# Re-run the security scan (0 critical / 0 high expected)
# See docs/scan/scan-report.md
```

## Related documents

- [`DEPENDENCIES.md`](DEPENDENCIES.md) — dependency selection & maintenance policy
- [`scan/scan-report.md`](scan/scan-report.md) — latest vulnerability scan result
- [`../THIRD_PARTY_LICENSES.md`](../THIRD_PARTY_LICENSES.md) — full license texts
- [`../SECURITY.md`](../SECURITY.md) — vulnerability reporting

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
