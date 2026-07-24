# Administrator guide — bulletproof-compliance-portal

Day-2 operations for running the compliance portal: authentication, secrets,
network isolation, session storage, rate limiting, observability, and auditor
provisioning. Pairs with [`CONFIG.md`](CONFIG.md) (every variable) and
[`../docker/README.md`](../docker/README.md) (container topology).

## Deployment modes

The application factory (`create_app(mode=...)`) produces two apps from one
codebase:

- **Internal portal** (`portal.main:app`, `APP_MODE=internal`) — the full
  compliance workspace. Deploy on a private/overlay network; do **not** expose
  it directly to the internet.
- **Public DSR portal** (`dsr_portal.main:app`, `APP_MODE=public`) — the
  self-service data-subject intake only. Expose behind a WAF. In public mode the
  OpenAPI docs (`/docs`, `/redoc`, `/openapi.json`) are disabled and the
  internal routers are not mounted.

Run one app per process. In containers, `docker/Dockerfile.portal` and
`docker/Dockerfile.dsr_portal` build the two images; `docker/compose.yaml` wires
both behind separate nginx proxies.

## Authentication (OIDC)

Outside development, authentication is OIDC using the PKCE authorization-code
flow. Configure:

| Variable | Purpose |
|----------|---------|
| `OIDC_ISSUER` | Identity provider issuer URL |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Client credentials |
| `OIDC_REDIRECT_URI` | Must match the provider's registered callback (`…/auth/callback`) |
| `OIDC_DISCOVERY` | `true` to use the provider's discovery document |
| `OIDC_GROUP_*` | Map IdP group claims to the five portal roles |

Role assignment comes from the IdP group claims mapped by `OIDC_GROUP_ADMIN`,
`OIDC_GROUP_COMPLIANCE_OFFICER`, `OIDC_GROUP_AUDITOR`, `OIDC_GROUP_SME`,
`OIDC_GROUP_VIEWER`. Group-claim validation guards against privilege escalation,
and the session token is rotated on OIDC callback to prevent session fixation.

**Development only:** with `APP_ENV=development` a `/auth/dev-login?role=<role>`
route is available so you can exercise the UI without an IdP. It is inert outside
development — never rely on it in staging/production.

## Sessions

- Sessions are stored in **Redis** when `REDIS_URL` is set (required for
  multi-worker deployments); otherwise an in-memory store is used (single-process
  development only).
- Cookie hardening is controlled by `SESSION_COOKIE_SECURE`,
  `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, and `SESSION_COOKIE_NAME`.
  Keep `SECURE=true` and `HTTPONLY=true` in production.
- `SESSION_SECRET` (32-byte random) signs sessions and CSRF tokens. Rotate it as
  a secret, not a config value.
- `SESSION_MAX_AGE_S` bounds session lifetime.

## Backing compliance service

The portal calls the compliance service over HTTP. Configure:

| Variable | Purpose |
|----------|---------|
| `COMPLIANCE_API_BASE_URL` | Service base URL |
| `COMPLIANCE_API_TOKEN` | Service-account bearer token |
| `COMPLIANCE_API_TIMEOUT_S` | Request timeout |
| `COMPLIANCE_API_CA_BUNDLE` | CA bundle for verifying the service certificate |
| `COMPLIANCE_API_CLIENT_CERT` / `COMPLIANCE_API_CLIENT_KEY` | Client cert/key for **mTLS** |

For mutual TLS, supply the client cert/key and the CA bundle; the portal verifies
the service certificate chain.

## Secrets management

In containers, secrets are file-mounted and read by `docker/entrypoint.sh` at
start (see `docker/secrets.example/` for the expected files). Do **not** bake
secrets into images or commit them. At minimum, provision: `SESSION_SECRET`, the
`OIDC_CLIENT_SECRET`, `COMPLIANCE_API_TOKEN`, database credentials, the CAPTCHA
secret (public portal), and any TLS material.

## Network isolation and proxies

- Put the **internal** portal on a private or overlay network (WireGuard,
  Tailscale, or an equivalent) with strict firewall rules — it holds
  sensitive audit data and decision controls and must never be reachable by
  unauthenticated users.
- Expose the **public** DSR portal to the internet only through a WAF.
- Set `TRUSTED_PROXIES` (CIDRs) so the forwarded-header middleware only honours
  `X-Forwarded-*` from your reverse proxies. The nginx configs in `docker/nginx/`
  bind to loopback and terminate TLS.

## Rate limiting

- The public portal's per-minute limit is `PUBLIC_RATE_LIMIT_PER_MIN`.
- The internal portal uses a higher fixed ceiling in production and is
  effectively unlimited in development (so link-checkers and browser test sweeps
  don't mask real bugs as 503s).
- Rate-limit counters live in Redis when configured.

## CAPTCHA (public portal)

Set `CAPTCHA_PROVIDER` (e.g. `hcaptcha`) with `CAPTCHA_SITE_KEY` and
`CAPTCHA_SECRET`. The intake form requires a passing CAPTCHA before a DSR is
accepted.

## Cryptographic signing

Regulatory report bundles and exported PDFs are **Ed25519-signed** and anchored
to a published JWKS. Configure `SIGNING_KEY_ID` and provision the signing key as
a secret. Verifiers validate signatures against the published JWKS.

## Observability

- **Health**: `GET /healthz` (liveness) and `GET /readyz` (readiness; checks
  downstream dependencies). Both are wired as container HEALTHCHECKs.
- **Metrics**: Prometheus metrics are exposed at `/metrics`.
- **Logging**: structured (JSON) logs via `structlog`. `LOG_LEVEL` controls
  verbosity. PII (email, phone, and similar) is redacted in logs.
- **Audit**: every significant action emits an audit event to the compliance
  service; audit logging is a first-class middleware, and security-relevant
  refusals (SoD blocks, rejected MFA nonces) are audited even on the failure path.

## Auditor provisioning

Admins provision external auditor engagements at
`/admin/auditor-engagements`. An engagement is **time-limited** and
**scope-enforced**: the auditor can only download the evidence, audit chains,
gate records, and model cards within their granted scope and window. Evidence
PDFs are watermarked with the auditor's identity. Provision the minimum scope
required and let engagements expire rather than revoking manually.

## Upgrades and security maintenance

- Dependencies are pinned in `requirements.txt`. Before publishing, run the
  security scan and keep **0 critical / 0 high** (latest result in
  [`scan/scan-report.md`](scan/scan-report.md)).
- Regenerate the SBOM after dependency changes (see [`SBOM.md`](SBOM.md)).
- Report vulnerabilities per [`../SECURITY.md`](../SECURITY.md); patch timelines
  are in [`../SECURITY-EOL.md`](../SECURITY-EOL.md).

## Related documents

- [`CONFIG.md`](CONFIG.md) — every configuration variable, in full
- [`INSTALL.md`](INSTALL.md) / [`INSTALLATION.md`](INSTALLATION.md) — install & run
- [`INCIDENT-RESPONSE.md`](INCIDENT-RESPONSE.md) — operational incident handling
- [`../docker/README.md`](../docker/README.md) — container topology & hardening
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system design

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
