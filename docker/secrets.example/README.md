# Docker Secrets — Example / Placeholder Files

This directory contains **PLACEHOLDER ONLY** secret files. Do NOT use these
values in any environment. They exist so `docker compose -f docker/compose.yaml
config` validates without errors during initial repository checkout.

## Required Secret Files

| File                              | Used By              | Purpose                                                |
|-----------------------------------|----------------------|--------------------------------------------------------|
| `oidc_client_secret.txt`          | portal               | OIDC client secret for IdP (Keycloak/Auth0/Okta)       |
| `session_secret.txt`              | portal, dsr_portal   | Cookie/session signing key (≥ 32 bytes)                |
| `compliance_service_token.txt`    | portal, dsr_portal   | Bearer token for the upstream compliance service API   |
| `db_password.txt`                 | postgres, portal     | Postgres password (dev profile)                        |

For production, also create these (not shipped as examples — generate per-deployment):

| File                              | Used By              | Purpose                                                |
|-----------------------------------|----------------------|--------------------------------------------------------|
| `group_role_mapping`              | portal               | OIDC group → portal role allowlist (AMD-20)            |
| `captcha_secret`                  | dsr_portal           | hCaptcha / Turnstile secret key                        |
| `public_token_secret`             | dsr_portal           | DSR per-request token signing key (separate namespace) |

## Bootstrap Steps (Production)

```bash
# 1. Create the real secrets directory (gitignored)
mkdir -p docker/secrets
chmod 700 docker/secrets

# 2. Generate strong secrets (32+ bytes for signing keys)
openssl rand -hex 32 > docker/secrets/session_secret
openssl rand -hex 32 > docker/secrets/public_token_secret
chmod 600 docker/secrets/*

# 3. Populate IdP / API tokens from your provisioning system
echo -n "<oidc-client-secret-from-keycloak>"   > docker/secrets/oidc_client_secret
echo -n "<compliance-service-bearer-token>"    > docker/secrets/compliance_service_token
echo -n "<hcaptcha-secret>"                    > docker/secrets/captcha_secret
echo -n "<postgres-password>"                  > docker/secrets/db_password
chmod 600 docker/secrets/*

# 4. Build the OIDC group-to-role mapping (AMD-20 — allowlisted by entrypoint)
cat > docker/secrets/group_role_mapping <<EOF
OIDC_GROUP_ADMIN=cn=portal-admins,ou=groups,dc=corp
OIDC_GROUP_COMPLIANCE_OFFICER=cn=compliance-officers,ou=groups,dc=corp
OIDC_GROUP_AUDITOR=cn=auditors,ou=groups,dc=corp
OIDC_GROUP_SME=cn=ai-smes,ou=groups,dc=corp
OIDC_GROUP_VIEWER=cn=portal-viewers,ou=groups,dc=corp
EOF
chmod 640 docker/secrets/group_role_mapping

# 5. Update docker/compose.yaml secrets: section to point at docker/secrets/*
#    (instead of docker/secrets.example/*).
```

## Rotation

Rotation does NOT require container recreation when secrets are mounted from
files. Update the file content on the host and signal the container, e.g.
`docker exec compliance-portal-internal kill -HUP 1`. The `entrypoint.sh`
re-loads secrets at process exec time only; for runtime rotation, the
application must be designed to re-read the env on signal — pending feature.

## Audit & Trust

Real `docker/secrets/` is gitignored (top-level `.gitignore` enforces this).
Never commit production secrets. Use a sealed-secrets / Vault / SOPS workflow
for shared environments. Each operator who has read access to host filesystem
can read these files; restrict accordingly.
