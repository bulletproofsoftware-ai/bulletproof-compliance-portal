#!/usr/bin/env sh
# WI-18 — Container entrypoint for both internal portal and public DSR portal.
#
# AMD-20 (CISO M-11): Source environment variables from file-mounted secrets
# under /run/secrets/* so they never appear in `docker inspect` env output and
# so they can be rotated without container recreation. Allowlist enforced for
# OIDC group-to-role mappings.
#
# Behavior:
#   1. For each known secret name, if /run/secrets/<name> exists, export
#      <NAME_UPPER>=<file-content>.
#   2. Parse /run/secrets/group_role_mapping (KEY=value lines) with allowlist
#      validation; reject unknown keys.
#   3. Validate required env vars depending on $APP_MODE (internal vs public).
#   4. exec the original CMD ($@).
#
# Errors are fatal — any missing required secret or unknown mapping key exits
# non-zero so the container fails fast and Docker restart-policy can react.

set -eu

log() {
    printf '[entrypoint] %s\n' "$*" >&2
}

err() {
    printf '[entrypoint][ERROR] %s\n' "$*" >&2
}

# ── Step 1: Load file-mounted secrets ─────────────────────────────────────────
# Allowlist of secret filenames we will source. Each becomes an UPPERCASE env
# var with the file content as its value.
SECRET_NAMES="
oidc_client_secret
session_secret
session_secret_public
compliance_api_token
compliance_api_token_public
public_token_secret
pg_dsn
db_password
captcha_secret
"

for name in $SECRET_NAMES; do
    path="/run/secrets/${name}"
    if [ -f "$path" ]; then
        # Convert lowercase secret name to uppercase env var name.
        env_name=$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')
        # shellcheck disable=SC2163
        value=$(cat "$path")
        export "${env_name}=${value}"
        log "loaded secret: ${env_name}"
    fi
done

# ── Step 2: Parse OIDC group-role mapping (allowlist validated) ───────────────
GROUP_MAPPING_FILE="/run/secrets/group_role_mapping"
if [ -f "$GROUP_MAPPING_FILE" ]; then
    log "parsing group_role_mapping"
    # Read line by line. Skip blanks and comments. Validate keys against
    # an explicit allowlist before exporting.
    while IFS='=' read -r key value || [ -n "$key" ]; do
        # Trim leading/trailing whitespace from key (POSIX-safe).
        key=$(printf '%s' "$key" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        case "$key" in
            ''|'#'*)
                continue
                ;;
            OIDC_GROUP_ADMIN|OIDC_GROUP_COMPLIANCE_OFFICER|OIDC_GROUP_AUDITOR|OIDC_GROUP_SME|OIDC_GROUP_VIEWER)
                # shellcheck disable=SC2163
                export "${key}=${value}"
                log "group_mapping: exported ${key}"
                ;;
            *)
                err "unknown group_role_mapping key '${key}' — refusing to export"
                exit 1
                ;;
        esac
    done < "$GROUP_MAPPING_FILE"
fi

# ── Step 3: Validate required env vars per APP_MODE ───────────────────────────
APP_MODE="${APP_MODE:-internal}"

require_env() {
    var=$1
    eval "val=\${${var}:-}"
    if [ -z "$val" ]; then
        err "required environment variable not set: ${var}"
        exit 1
    fi
}

case "$APP_MODE" in
    internal)
        # Internal portal needs session secret + OIDC secret + compliance token.
        # Pre-existing portal config defaults are permissive in dev; in prod we
        # treat missing values as fatal.
        if [ "${APP_ENV:-}" = "production" ]; then
            require_env SESSION_SECRET
            require_env OIDC_CLIENT_SECRET
            require_env COMPLIANCE_API_TOKEN
        fi
        ;;
    public)
        # F-06 — the public portal MUST have a session secret and a public
        # token signing secret that are distinct from the internal portal.
        # SESSION_SECRET_PUBLIC and PUBLIC_TOKEN_SECRET are mounted from
        # separate files in compose.yaml; we validate they are present in
        # production and (best-effort) that they differ from each other.
        if [ "${APP_ENV:-}" = "production" ]; then
            require_env SESSION_SECRET_PUBLIC
            require_env PUBLIC_TOKEN_SECRET
            require_env COMPLIANCE_API_TOKEN_PUBLIC
            if [ "${SESSION_SECRET_PUBLIC}" = "${PUBLIC_TOKEN_SECRET}" ]; then
                err "SESSION_SECRET_PUBLIC and PUBLIC_TOKEN_SECRET must NOT match (F-06 key separation)"
                exit 1
            fi
            # Defence-in-depth: if SESSION_SECRET (internal) is also somehow
            # present in this container, refuse to start if the public
            # session secret matches it.
            if [ -n "${SESSION_SECRET:-}" ] && [ "${SESSION_SECRET}" = "${SESSION_SECRET_PUBLIC}" ]; then
                err "SESSION_SECRET (internal) and SESSION_SECRET_PUBLIC must NOT match"
                exit 1
            fi
        fi
        ;;
    *)
        err "unknown APP_MODE: ${APP_MODE}"
        exit 1
        ;;
esac

log "APP_MODE=${APP_MODE} APP_ENV=${APP_ENV:-unset} — handing off to: $*"

# ── Step 4: exec to the actual server process ────────────────────────────────
exec "$@"
