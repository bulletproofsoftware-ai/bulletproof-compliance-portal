# Configuration Reference

This document provides a complete reference for all environment variables and configuration options for the Compliance Portal.

## Table of Contents

1. [Overview](#overview)
2. [Configuration Sources](#configuration-sources)
3. [Environment Variables](#environment-variables)
4. [App Identity](#app-identity)
5. [Network Binding](#network-binding)
6. [Compliance Service Integration](#compliance-service-integration)
7. [OIDC Authentication](#oidc-authentication)
8. [Session Management](#session-management)
9. [Data Store Configuration](#data-store-configuration)
10. [Public DSR Portal](#public-dsr-portal)
11. [Optional Integrations](#optional-integrations)
12. [Security Configuration](#security-configuration)
13. [Configuration Examples](#configuration-examples)
14. [Validation and Startup](#validation-and-startup)

## Overview

The Compliance Portal uses environment variables for all configuration. This allows:

- **Environment parity**: Same codebase runs in development, staging, and production with different configurations
- **Secret management**: Sensitive values (tokens, keys, secrets) are never committed to version control
- **Containerization**: Docker containers are configured at runtime via environment injection
- **Infrastructure as Code**: Kubernetes manifests and docker-compose files define all configuration declaratively

Configuration is loaded at application startup via `src/portal/config.py`, which validates all required variables and provides helpful error messages if configuration is missing or invalid.

## Configuration Sources

Configuration is read from multiple sources in order of precedence:

1. **Environment variables** (highest priority) — actual OS environment or Docker container environment
2. **.env file** (development only) — `.env` file in the project root, loaded by python-dotenv (only in development mode)
3. **Default values** (lowest priority) — hardcoded defaults in `src/portal/config.py`

### Development Workflow

```bash
# 1. Copy the example configuration
cp .env.example .env

# 2. Edit .env with your local values
# For local dev, most external services can be mocked or skipped

# 3. Run the application
make run
# .env is automatically loaded by python-dotenv
```

### Production Deployment

In production, environment variables are injected via:

- **Docker containers**: Environment variables defined in `docker-compose.yml` or passed via `-e` flags
- **Kubernetes**: Environment variables defined in Kubernetes manifests or ConfigMaps
- **Systemd/supervisord**: Environment variables defined in service unit files

**.env files are NEVER used in production.** Secrets are managed by your infrastructure's secrets backend (Vault, AWS Secrets Manager, Kubernetes Secrets, etc.).

## Environment Variables

All environment variables are organized by functional domain.

### Variable Types

Each variable is classified by:

- **Type**: String, Integer, Float, Boolean, URI
- **Required**: Whether the variable must be set (true/false)
- **Default**: Default value if not provided
- **Scope**: Whether it applies to internal portal, public portal, or both
- **Sensitivity**: Whether the value should be treated as a secret

| Sensitivity Level | Description |
|-------------------|-------------|
| `public` | Can be logged and displayed (non-sensitive) |
| `internal` | Can be logged in development but not production (internal values) |
| `secret` | Sensitive value; never logged; requires careful handling |

## App Identity

These variables define how the application identifies itself and behaves.

### APP_MODE

Controls which portal(s) the application runs as.

- **Type**: String (enum)
- **Required**: Yes
- **Default**: None
- **Scope**: Both
- **Sensitivity**: Public
- **Allowed values**: `internal`, `public`, `dual`

```bash
# Internal portal only (WI-03 + AMD-03)
APP_MODE=internal

# Public DSR portal only (WI-09)
APP_MODE=public

# Both portals in same container (advanced)
APP_MODE=dual
```

**Implications**:
- `internal`: Runs on `INTERNAL_HOST:INTERNAL_PORT`, requires OIDC authentication, shows audit explorer
- `public`: Runs on `PUBLIC_HOST:PUBLIC_PORT`, requires CAPTCHA but no authentication, shows DSR submission form
- `dual`: Runs both on separate ports in same process (not recommended for production)

### APP_ENV

Determines whether the application runs in development, staging, or production mode.

- **Type**: String (enum)
- **Required**: Yes
- **Default**: None
- **Scope**: Both
- **Sensitivity**: Public
- **Allowed values**: `development`, `staging`, `production`

```bash
APP_ENV=development
```

**Implications**:

| Value | Behavior |
|-------|----------|
| `development` | Auto-reload on file changes, verbose logging, .env file loaded, HTTPS/TLS optional |
| `staging` | Same as production but with test data, HTTPS/TLS required |
| `production` | No auto-reload, strict validation, HTTPS/TLS required, no .env loading |

### LOG_LEVEL

Controls the verbosity of application logging.

- **Type**: String (enum)
- **Required**: No
- **Default**: `INFO`
- **Scope**: Both
- **Sensitivity**: Public
- **Allowed values**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

```bash
# Development: verbose logging
LOG_LEVEL=DEBUG

# Production: normal logging
LOG_LEVEL=INFO

# Production: minimal logging
LOG_LEVEL=WARNING
```

**Behavior by level**:

| Level | Includes |
|-------|----------|
| DEBUG | Everything; very noisy; see request/response bodies (redacted PII per AMD-17) |
| INFO | Request summaries, configuration loaded, startup messages |
| WARNING | Configuration issues, degraded services, rate limit hits |
| ERROR | Failures requiring operator attention |
| CRITICAL | System-level failures (startup failure, database offline) |

## Network Binding

These variables control which network addresses the application listens on.

### INTERNAL_HOST

Host/IP address the internal portal listens on.

- **Type**: String (IP address or hostname)
- **Required**: No
- **Default**: `0.0.0.0` (all interfaces)
- **Scope**: Internal portal only
- **Sensitivity**: Public

```bash
# Listen on all interfaces (default for Docker)
INTERNAL_HOST=0.0.0.0

# Listen on localhost only (local dev)
INTERNAL_HOST=127.0.0.1

# Listen on specific IP
INTERNAL_HOST=10.0.1.15
```

### INTERNAL_PORT

Port number the internal portal listens on.

- **Type**: Integer (1-65535)
- **Required**: No
- **Default**: `8080`
- **Scope**: Internal portal only
- **Sensitivity**: Public

```bash
INTERNAL_PORT=8080
```

**Security note**: In production, the portal runs behind a reverse proxy (nginx) which handles TLS on port 8443. The container port 8080 is internal and not exposed to the internet.

### PUBLIC_HOST

Host/IP address the public DSR portal listens on.

- **Type**: String (IP address or hostname)
- **Required**: No
- **Default**: `0.0.0.0` (all interfaces)
- **Scope**: Public DSR portal only
- **Sensitivity**: Public

```bash
PUBLIC_HOST=0.0.0.0
```

### PUBLIC_PORT

Port number the public DSR portal listens on.

- **Type**: Integer (1-65535)
- **Required**: No
- **Default**: `8081`
- **Scope**: Public DSR portal only
- **Sensitivity**: Public

```bash
PUBLIC_PORT=8081
```

## Compliance Service Integration

These variables configure the connection to the compliance service (WI-03).

The compliance service is an external microservice that the portal queries for:
- Audit events (for the audit explorer, WI-05)
- Compliance metrics and controls
- Assessment status for gate decisions (WI-04)

### COMPLIANCE_API_BASE_URL

Base URL for the compliance service API.

- **Type**: URI
- **Required**: Yes (unless compliance service is mocked/unavailable)
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Internal (contains domain name but not secrets)

```bash
# Production: internal service mesh
COMPLIANCE_API_BASE_URL=https://compliance-svc.internal/api/v1/compliance

# Local dev: use mock
COMPLIANCE_API_BASE_URL=http://localhost:9000/api/v1/compliance
```

**Note**: If unreachable, the portal continues operating with graceful degradation (queries return empty results; tests mock the service).

### COMPLIANCE_API_TOKEN

Bearer token for authenticating to the compliance service.

- **Type**: String
- **Required**: Yes (if compliance service is used)
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Secret

```bash
# Production: service account token
COMPLIANCE_API_TOKEN=<set-your-compliance-api-token>...

# Local dev: placeholder
COMPLIANCE_API_TOKEN=<set-your-compliance-api-token>
```

This token is passed in the `Authorization: Bearer <token>` header on all compliance service requests.

### COMPLIANCE_API_TIMEOUT_S

HTTP request timeout for compliance service queries (in seconds).

- **Type**: Float
- **Required**: No
- **Default**: `10.0`
- **Scope**: Internal portal only
- **Sensitivity**: Public

```bash
# Standard timeout (10 seconds)
COMPLIANCE_API_TIMEOUT_S=10.0

# For slow networks
COMPLIANCE_API_TIMEOUT_S=30.0

# Aggressive (for latency-sensitive operations)
COMPLIANCE_API_TIMEOUT_S=5.0
```

### COMPLIANCE_API_CA_BUNDLE

Path to CA certificate bundle for mTLS (optional, mutual TLS authentication).

- **Type**: File path
- **Required**: No
- **Default**: (none; uses system CA store)
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
# mTLS Option A: with custom CA bundle (see COMPLIANCE_API_CLIENT_CERT below)
COMPLIANCE_API_CA_BUNDLE=/etc/ssl/certs/custom-ca-bundle.pem
```

If set, the portal validates the compliance service's certificate against this CA bundle. Required when the compliance service uses a self-signed or internal CA certificate.

### COMPLIANCE_API_CLIENT_CERT

Path to client certificate for mTLS (optional).

- **Type**: File path
- **Required**: No (unless COMPLIANCE_API_CA_BUNDLE is set)
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
COMPLIANCE_API_CLIENT_CERT=/etc/ssl/certs/compliance-client.crt
```

Combines with `COMPLIANCE_API_CLIENT_KEY` to form a client certificate pair for mutual TLS authentication. See WI-03 and AMD-10 for implementation details.

### COMPLIANCE_API_CLIENT_KEY

Path to client private key for mTLS (optional).

- **Type**: File path
- **Required**: No (unless COMPLIANCE_API_CLIENT_CERT is set)
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Secret

```bash
COMPLIANCE_API_CLIENT_KEY=/etc/ssl/certs/compliance-client.key
```

Private key corresponding to `COMPLIANCE_API_CLIENT_CERT`. In Docker/Kubernetes, this file is mounted from a secrets volume.

**mTLS Configuration**: To enable mTLS authentication (AMD-10), set all three:
1. `COMPLIANCE_API_CA_BUNDLE=...` (server's CA certificate)
2. `COMPLIANCE_API_CLIENT_CERT=...` (client certificate)
3. `COMPLIANCE_API_CLIENT_KEY=...` (client private key)

If not set, the portal falls back to bearer token authentication (COMPLIANCE_API_TOKEN).

## OIDC Authentication

These variables configure OpenID Connect authentication (WI-02).

OIDC is used to authenticate internal portal users against a central identity provider (such as Okta, Keycloak, or Entra ID). The portal does not store passwords; it delegates authentication to the OIDC provider and receives claims that are mapped to roles.

### OIDC_ISSUER

OIDC provider issuer URL (authority endpoint).

- **Type**: URI
- **Required**: Yes
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
# Okta
OIDC_ISSUER=https://acme.okta.com/oauth2/default/

# Keycloak
OIDC_ISSUER=https://keycloak.internal/realms/compliance-portal/

# Entra ID
OIDC_ISSUER=https://login.microsoftonline.com/TENANT_ID/v2.0/
```

The portal uses this URL to fetch the OIDC discovery document (`.well-known/openid-configuration`) unless `OIDC_DISCOVERY=false` is set.

### OIDC_CLIENT_ID

OIDC application/client ID registered with the identity provider.

- **Type**: String
- **Required**: Yes
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
OIDC_CLIENT_ID=compliance-portal-internal
```

This is a public identifier (not a secret) that identifies the application to the OIDC provider.

### OIDC_CLIENT_SECRET

OIDC application secret issued by the identity provider.

- **Type**: String
- **Required**: Yes
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Secret

```bash
OIDC_CLIENT_SECRET=<your-oidc-client-secret>
```

This is a secret credential used in the authorization code exchange (backend-to-backend); it must be kept secure and never logged.

### OIDC_REDIRECT_URI

OAuth 2.0 redirect URI after the user authenticates at the OIDC provider.

- **Type**: URI
- **Required**: Yes
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
# Production (TLS required)
OIDC_REDIRECT_URI=https://portal.internal/auth/callback

# Local development (HTTP OK for localhost)
OIDC_REDIRECT_URI=http://localhost:8080/auth/callback
```

This URI must be registered in the OIDC provider's allowed redirect URIs (security requirement; prevents redirect hijacking).

### OIDC_DISCOVERY

Whether to fetch OIDC configuration from the discovery endpoint.

- **Type**: Boolean (true/false)
- **Required**: No
- **Default**: `true`
- **Scope**: Internal portal only
- **Sensitivity**: Public

```bash
# Production: use discovery endpoint (recommended)
OIDC_DISCOVERY=true

# Local dev or strict security: disable discovery
OIDC_DISCOVERY=false
```

If `true`, the portal fetches the OIDC discovery document from `OIDC_ISSUER/.well-known/openid-configuration` to obtain endpoints (authorization, token, userinfo, jwks_uri). This is the standard and recommended approach.

If `false`, all OIDC endpoints must be explicitly configured (not shown here; see `src/portal/config.py` for advanced options).

### OIDC_GROUP_* (Role Mapping)

Maps OIDC group claims to Compliance Portal roles.

- **Type**: String
- **Required**: No (but recommended for production)
- **Default**: None
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
OIDC_GROUP_ADMIN=compliance-portal-admin
OIDC_GROUP_COMPLIANCE_OFFICER=compliance-portal-officer
OIDC_GROUP_AUDITOR=compliance-portal-auditor
OIDC_GROUP_SME=compliance-portal-sme
OIDC_GROUP_VIEWER=compliance-portal-viewer
```

When a user logs in via OIDC:
1. The OIDC provider returns the user's group memberships in a `groups` claim
2. The portal checks if any of the user's groups match the configured group names
3. If a match is found, the user is assigned the corresponding role

For example, if a user is in the `compliance-portal-officer` group (from OIDC), the portal assigns them the `compliance_officer` role (WI-02).

**Role Hierarchy** (by privilege level):

1. `admin` — System administration, all permissions
2. `compliance_officer` — Compliance operations, decision authority
3. `auditor` — Read-only audit log access, evidence downloads
4. `sme` — Subject Matter Expert, model card approvals
5. `viewer` — Read-only dashboard access, no downloads

If group mapping is not configured, all users receive the `viewer` role by default.

## Session Management

These variables control how user sessions are created, stored, and validated.

### SESSION_SECRET

Secret key used to sign session cookies (WI-02, AMD-15).

- **Type**: String (minimum 32 bytes)
- **Required**: Yes
- **Default**: None
- **Scope**: Both
- **Sensitivity**: Secret

```bash
# Generate a secure random string (32+ bytes)
openssl rand -hex 32
# Output: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

SESSION_SECRET=<set-your-session-secret>
```

Used to HMAC-sign session cookies. If the secret is leaked or rotated, all sessions are invalidated (users must re-authenticate).

### SESSION_MAX_AGE_S

Maximum session lifetime in seconds.

- **Type**: Integer
- **Required**: No
- **Default**: `3600` (1 hour)
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Short session (high security)
SESSION_MAX_AGE_S=1800  # 30 minutes

# Standard session (default)
SESSION_MAX_AGE_S=3600  # 1 hour

# Long session (low security; not recommended for production)
SESSION_MAX_AGE_S=86400  # 24 hours
```

If a user's session cookie is older than this value, they are logged out and must re-authenticate.

### SESSION_COOKIE_NAME

Name of the session cookie.

- **Type**: String
- **Required**: No
- **Default**: `cp_session`
- **Scope**: Both
- **Sensitivity**: Public

```bash
SESSION_COOKIE_NAME=cp_session
```

The cookie is set in Set-Cookie response headers with this name.

### SESSION_COOKIE_SECURE

Whether the session cookie is marked as "Secure" (HTTPS only).

- **Type**: Boolean (true/false)
- **Required**: No
- **Default**: `true`
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Production: HTTPS only (required)
SESSION_COOKIE_SECURE=true

# Local dev over HTTP (development only)
SESSION_COOKIE_SECURE=false
```

If `true`, the browser only sends the cookie over HTTPS connections, preventing it from being transmitted over unencrypted HTTP.

### SESSION_COOKIE_HTTPONLY

Whether the session cookie is marked as "HttpOnly" (not accessible to JavaScript).

- **Type**: Boolean (true/false)
- **Required**: No
- **Default**: `true`
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Always recommended
SESSION_COOKIE_HTTPONLY=true
```

If `true`, JavaScript cannot access the cookie (prevents session hijacking via XSS). This should always be `true`.

### SESSION_COOKIE_SAMESITE

SameSite attribute for the session cookie (CSRF protection).

- **Type**: String (enum: `strict`, `lax`, `none`)
- **Required**: No
- **Default**: `lax`
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Strict (recommended): cookie never sent cross-site
SESSION_COOKIE_SAMESITE=strict

# Lax (default): cookie sent on top-level navigation
SESSION_COOKIE_SAMESITE=lax

# None (requires Secure): cookie sent cross-site (for APIs)
SESSION_COOKIE_SAMESITE=none
```

Controls when the browser includes the session cookie in requests:
- `strict`: Never in cross-site requests (prevents CSRF)
- `lax`: Only in top-level navigation (user clicks a link)
- `none`: Always (requires `SESSION_COOKIE_SECURE=true`)

### REDIS_URL

Redis connection string for server-side session storage.

- **Type**: URI
- **Required**: No
- **Default**: (none; in-memory fallback)
- **Scope**: Both
- **Sensitivity**: Internal

```bash
# Local development
REDIS_URL=redis://localhost:6379/0

# Production with authentication
REDIS_URL=redis://:password@redis.internal:6379/0

# Production with TLS
REDIS_URL=rediss://:password@redis.internal:6380/0

# Leave blank for in-memory storage (testing/dev only)
REDIS_URL=
```

If set, user sessions are stored in Redis (shared across container restarts). If not set, sessions are stored in-memory (lost on restart; only suitable for development and testing).

## Data Store Configuration

These variables configure connections to PostgreSQL (for read-only views) and Qdrant (for knowledge indexing).

### PG_DSN

PostgreSQL connection string.

- **Type**: URI
- **Required**: No (unless PostgreSQL features are used)
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Secret (if it contains a password)

```bash
# Development (local PostgreSQL)
PG_DSN=postgresql+asyncpg://portal:portal@localhost:5432/compliance_portal

# Production (with password)
PG_DSN=postgresql+asyncpg://portal:$DB_PASSWORD@postgres.internal:5432/compliance_portal

# Production (with SSL/TLS)
PG_DSN=postgresql+asyncpg://portal:$DB_PASSWORD@postgres.internal:5432/compliance_portal?ssl=require

# Leave blank to skip PostgreSQL (tests mock the database)
PG_DSN=
```

Used to connect to PostgreSQL for:
- Read-only views of compliance data (WI-13)
- Audit event queries (WI-05)
- DSR submission storage (WI-09)

Connection pool is configured automatically; a typical pool size is 5-10 connections.

### QDRANT_URL

Qdrant vector database connection URL.

- **Type**: URI
- **Required**: No (unless knowledge indexing is enabled)
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
# Local development (in-memory)
QDRANT_URL=http://localhost:6333

# Production (remote cluster)
QDRANT_URL=https://qdrant.internal:6333

# Leave blank to skip Qdrant (tests mock the service)
QDRANT_URL=
```

Used to connect to Qdrant for:
- Semantic search of process knowledge (WI-14)
- Evidence similarity matching (WI-13)
- LLM embedding operations

### QDRANT_API_KEY

API key for Qdrant authentication (optional).

- **Type**: String
- **Required**: No
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Secret

```bash
# If Qdrant requires API key authentication
QDRANT_API_KEY=<set-your-api-key>
```

If set, this key is passed in the `api-key` header on all Qdrant requests.

## Public DSR Portal

These variables configure the public Data Subject Request (DSR) portal (WI-09).

### CAPTCHA_PROVIDER

CAPTCHA provider for the public DSR portal.

- **Type**: String (enum: `hcaptcha`, `recaptcha`)
- **Required**: No
- **Default**: `hcaptcha`
- **Scope**: Public portal only
- **Sensitivity**: Public

```bash
# reCAPTCHA v3
CAPTCHA_PROVIDER=recaptcha

# hCaptcha (privacy-friendly alternative)
CAPTCHA_PROVIDER=hcaptcha
```

Controls which CAPTCHA service validates user submissions on the DSR form (prevents bot abuse).

### CAPTCHA_SITE_KEY

Public CAPTCHA site key.

- **Type**: String
- **Required**: Conditionally (required if public DSR is enabled)
- **Default**: (none)
- **Scope**: Public portal only
- **Sensitivity**: Public (site keys are public; secrets are not)

```bash
# hCaptcha
CAPTCHA_SITE_KEY=<set-your-captcha-site-key>

# reCAPTCHA
CAPTCHA_SITE_KEY=<set-your-captcha-site-key>
```

This key is embedded in the DSR form and used by the browser to render the CAPTCHA challenge.

### CAPTCHA_SECRET

Secret CAPTCHA key (kept server-side).

- **Type**: String
- **Required**: Conditionally (required if public DSR is enabled)
- **Default**: (none)
- **Scope**: Public portal only
- **Sensitivity**: Secret

```bash
CAPTCHA_SECRET=0x4AAAAAAABNhpDXq3NR_8s5TvM2c5m_LM7_x_x_x_x
```

Used by the server to verify CAPTCHA responses from the browser. Never exposed to the client.

### PUBLIC_RATE_LIMIT_PER_MIN

Rate limit for public DSR submissions (requests per minute).

- **Type**: Integer
- **Required**: No
- **Default**: `100`
- **Scope**: Public portal only
- **Sensitivity**: Public

```bash
# Strict (1 request per minute per IP)
PUBLIC_RATE_LIMIT_PER_MIN=1

# Moderate (10 requests per minute)
PUBLIC_RATE_LIMIT_PER_MIN=10

# Permissive (100 requests per minute; default)
PUBLIC_RATE_LIMIT_PER_MIN=100
```

Prevents abuse of the public DSR form. Tracking is per client IP address (respected via `X-Forwarded-For` if behind a trusted proxy; see `TRUSTED_PROXIES`).

## Optional Integrations

### MARKDOWN_PROXY_URL

Optional proxy for fetching markdown documents from external sources.

- **Type**: URI
- **Required**: No
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Internal

```bash
# Optional: fetch compliance documentation from external markdown service
MARKDOWN_PROXY_URL=https://docs.internal/api/markdown

# Leave blank to skip markdown proxying
MARKDOWN_PROXY_URL=
```

If set, the portal can fetch and render markdown documents from this endpoint (WI-16, project documentation portal).

## Security Configuration

### SIGNING_KEY_ID

Ed25519 private key identifier for document signing (WI-12, AMD-04).

- **Type**: String (key identifier or path to key file)
- **Required**: Conditionally (required if PDF export with signatures is enabled)
- **Default**: (none)
- **Scope**: Internal portal only
- **Sensitivity**: Secret

```bash
# Key identifier (private key loaded from secrets)
SIGNING_KEY_ID=key-2024-v1

# Or path to key file (for Docker volume mount)
SIGNING_KEY_ID=/etc/secrets/signing-key.pem
```

Used to cryptographically sign evidence documents and compliance reports. The signing public key is published via a JWKS endpoint for signature verification.

### TRUSTED_PROXIES

Comma-separated list of CIDR ranges from which proxy headers are trusted.

- **Type**: String (comma-separated CIDR blocks)
- **Required**: No
- **Default**: `127.0.0.1/32`
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Localhost only (development)
TRUSTED_PROXIES=127.0.0.1/32

# Behind nginx proxy
TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8

# Behind AWS ALB
TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12
```

When the application is behind a reverse proxy or load balancer, the real client IP is in `X-Forwarded-For` header. The portal trusts this header only from listed CIDR ranges (security requirement; prevents IP spoofing).

### CORS_ALLOWED_ORIGINS

Comma-separated list of allowed origins for Cross-Origin Resource Sharing.

- **Type**: String (comma-separated URIs)
- **Required**: No
- **Default**: (none; CORS disabled)
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Single origin
CORS_ALLOWED_ORIGINS=https://portal.internal

# Multiple origins (space-separated or semicolon-separated)
CORS_ALLOWED_ORIGINS=https://portal.internal,https://dashboard.internal

# Wildcard (development only; not recommended for production)
CORS_ALLOWED_ORIGINS=*
```

Controls which external origins (websites, SPAs) can make requests to the portal's API. If not set, CORS is disabled and cross-origin requests are rejected.

### BEHAVIOR_HOOK_ENABLED

Feature flag to enable behavioral event hooks (PRD 11, experimental).

- **Type**: Boolean (true/false)
- **Required**: No
- **Default**: `false`
- **Scope**: Both
- **Sensitivity**: Public

```bash
# Disable behavioral hooks (default)
BEHAVIOR_HOOK_ENABLED=false

# Enable behavioral hooks (experimental)
BEHAVIOR_HOOK_ENABLED=true
```

If enabled, the portal sends behavioral events (user actions, decisions) to an external hook endpoint (see `BEHAVIOR_HOOK_URL`).

### BEHAVIOR_HOOK_URL

Endpoint for behavioral event webhooks (PRD 11, experimental).

- **Type**: URI
- **Required**: Conditionally (required if BEHAVIOR_HOOK_ENABLED=true)
- **Default**: (none)
- **Scope**: Both
- **Sensitivity**: Internal

```bash
# Example webhook endpoint
BEHAVIOR_HOOK_URL=https://analytics.internal/api/events

# Leave blank if BEHAVIOR_HOOK_ENABLED=false
BEHAVIOR_HOOK_URL=
```

Used to send event payloads to external analytics or behavioral tracking services. Only active if `BEHAVIOR_HOOK_ENABLED=true`.

## Configuration Examples

### Development Configuration

```bash
# .env (local development)
APP_MODE=internal
APP_ENV=development
LOG_LEVEL=DEBUG

INTERNAL_HOST=127.0.0.1
INTERNAL_PORT=8080
PUBLIC_HOST=127.0.0.1
PUBLIC_PORT=8081

# Compliance service: mocked in tests
COMPLIANCE_API_BASE_URL=https://compliance-svc.internal/api/v1/compliance
COMPLIANCE_API_TOKEN=dev-token

# OIDC: mocked or disabled
OIDC_ISSUER=https://auth.example.com/
OIDC_CLIENT_ID=local-dev
OIDC_CLIENT_SECRET=dev-secret
OIDC_REDIRECT_URI=http://localhost:8080/auth/callback
OIDC_DISCOVERY=false

# Sessions: in-memory for dev
SESSION_SECRET=<set-your-session-secret>
SESSION_COOKIE_SECURE=false
REDIS_URL=

# Data stores: optional
PG_DSN=
QDRANT_URL=

# Public portal: CAPTCHA not validated in tests
CAPTCHA_PROVIDER=hcaptcha
CAPTCHA_SITE_KEY=<set-your-captcha-site-key>
CAPTCHA_SECRET=

# Security: signing disabled in tests
SIGNING_KEY_ID=

# Proxies
TRUSTED_PROXIES=127.0.0.1/32
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

### Staging Configuration

```bash
# .env.staging
APP_MODE=internal
APP_ENV=staging
LOG_LEVEL=INFO

INTERNAL_HOST=0.0.0.0
INTERNAL_PORT=8080
PUBLIC_HOST=0.0.0.0
PUBLIC_PORT=8081

COMPLIANCE_API_BASE_URL=https://compliance-svc.staging/api/v1/compliance
COMPLIANCE_API_TOKEN=${COMPLIANCE_API_TOKEN}  # From environment
COMPLIANCE_API_CA_BUNDLE=/etc/ssl/certs/staging-ca.pem
COMPLIANCE_API_CLIENT_CERT=/etc/ssl/certs/staging-client.crt
COMPLIANCE_API_CLIENT_KEY=/etc/ssl/certs/staging-client.key

OIDC_ISSUER=https://auth.staging/
OIDC_CLIENT_ID=compliance-portal-staging
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
OIDC_REDIRECT_URI=https://portal.staging/auth/callback
OIDC_DISCOVERY=true
OIDC_GROUP_ADMIN=portal-staging-admin
OIDC_GROUP_COMPLIANCE_OFFICER=portal-staging-officer
OIDC_GROUP_AUDITOR=portal-staging-auditor
OIDC_GROUP_SME=portal-staging-sme
OIDC_GROUP_VIEWER=portal-staging-viewer

SESSION_SECRET=${SESSION_SECRET}  # 32+ bytes
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
REDIS_URL=redis://redis.staging:6379/0

PG_DSN=postgresql+asyncpg://portal:${DB_PASSWORD}@postgres.staging:5432/compliance_portal?ssl=require
QDRANT_URL=https://qdrant.staging:6333
QDRANT_API_KEY=${QDRANT_API_KEY}

CAPTCHA_PROVIDER=hcaptcha
CAPTCHA_SITE_KEY=${CAPTCHA_SITE_KEY}
CAPTCHA_SECRET=${CAPTCHA_SECRET}
PUBLIC_RATE_LIMIT_PER_MIN=100

SIGNING_KEY_ID=/etc/secrets/signing-key.pem

TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12
CORS_ALLOWED_ORIGINS=https://portal.staging
```

### Production Configuration

```bash
# In Kubernetes ConfigMap / Secrets
APP_MODE=dual  # Run both internal and public portals
APP_ENV=production
LOG_LEVEL=INFO

INTERNAL_HOST=0.0.0.0
INTERNAL_PORT=8080
PUBLIC_HOST=0.0.0.0
PUBLIC_PORT=8081

COMPLIANCE_API_BASE_URL=https://compliance-svc.internal/api/v1/compliance
COMPLIANCE_API_CA_BUNDLE=/etc/ssl/certs/prod-ca.pem
COMPLIANCE_API_CLIENT_CERT=/etc/ssl/certs/prod-client.crt
COMPLIANCE_API_CLIENT_KEY=/etc/ssl/certs/prod-client.key

OIDC_ISSUER=https://auth.prod/
OIDC_CLIENT_ID=compliance-portal
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}  # From Kubernetes Secret
OIDC_REDIRECT_URI=https://portal.internal/auth/callback
OIDC_DISCOVERY=true
OIDC_GROUP_ADMIN=compliance-portal-admin
OIDC_GROUP_COMPLIANCE_OFFICER=compliance-portal-officer
OIDC_GROUP_AUDITOR=compliance-portal-auditor
OIDC_GROUP_SME=compliance-portal-sme
OIDC_GROUP_VIEWER=compliance-portal-viewer

SESSION_SECRET=${SESSION_SECRET}  # From Kubernetes Secret
SESSION_COOKIE_SECURE=true
SESSION_COOKIE_HTTPONLY=true
SESSION_MAX_AGE_S=3600
REDIS_URL=redis://:${REDIS_PASSWORD}@redis.internal:6379/0

PG_DSN=postgresql+asyncpg://portal:${DB_PASSWORD}@postgres.internal:5432/compliance_portal?ssl=require
QDRANT_URL=https://qdrant.internal:6333
QDRANT_API_KEY=${QDRANT_API_KEY}

CAPTCHA_PROVIDER=hcaptcha
CAPTCHA_SITE_KEY=${CAPTCHA_SITE_KEY}
CAPTCHA_SECRET=${CAPTCHA_SECRET}
PUBLIC_RATE_LIMIT_PER_MIN=100

MARKDOWN_PROXY_URL=https://docs.internal/api/markdown

SIGNING_KEY_ID=/etc/secrets/signing-key.pem

TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8,172.16.0.0/12
CORS_ALLOWED_ORIGINS=https://portal.internal

BEHAVIOR_HOOK_ENABLED=false
```

## Validation and Startup

### Configuration Validation

Configuration is validated at application startup via `src/portal/config.py`. The application:

1. **Loads** environment variables from OS or `.env` file
2. **Validates** that all required variables are set
3. **Parses** and type-checks each variable
4. **Reports** helpful error messages for missing or invalid configuration

### Startup Checks

Before the application becomes ready to receive requests, it verifies:

- OIDC configuration is valid (can reach discovery endpoint if `OIDC_DISCOVERY=true`)
- Compliance service is reachable (or gracefully handle unavailability)
- Redis is available (if `REDIS_URL` is set)
- PostgreSQL is accessible (if `PG_DSN` is set)
- Qdrant is accessible (if `QDRANT_URL` is set)

If startup checks fail, the application exits with a clear error message.

### Configuration Reloading

Configuration is **NOT** reloaded at runtime. To apply configuration changes:

1. Update environment variables
2. Stop the running application
3. Start the application again (configuration is re-read)

This design ensures that running instances do not suddenly change behavior mid-request.

### Debugging Configuration

To inspect the loaded configuration at runtime:

```bash
# View all configuration (secrets redacted)
curl http://localhost:8080/debug/config

# Example output:
# {
#   "app_mode": "internal",
#   "app_env": "development",
#   "oidc_issuer": "https://auth.example.com/",
#   "internal_port": 8080,
#   ... (secrets redacted) ...
# }
```

This endpoint is only available in development mode (`APP_ENV=development`) for debugging purposes.
