"""Application settings — single source of environment truth.

All env access in the portal MUST go through this module. Anywhere else that
imports `os.environ` directly is a violation of WI-01 and should be rejected
in code review.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


AppMode = Literal["internal", "public"]
AppEnv = Literal["development", "staging", "production", "test"]


class Settings(BaseSettings):
    """Strongly-typed settings loaded from environment + .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── App identity ────────────────────────────────────────────────────────
    app_mode: AppMode = "internal"
    app_env: AppEnv = "development"
    log_level: str = Field(default="INFO")

    # ─── Bind ────────────────────────────────────────────────────────────────
    internal_host: str = "0.0.0.0"
    internal_port: int = 8080
    public_host: str = "0.0.0.0"
    public_port: int = 8081

    # ─── Compliance service (WI-03) ──────────────────────────────────────────
    compliance_api_base_url: HttpUrl = Field(
        default=HttpUrl("https://compliance-svc.local/api/v1/compliance")
    )
    compliance_api_token: SecretStr = Field(default=SecretStr("dev-token"))
    compliance_api_timeout_s: float = 10.0

    # WI-03 / AMD-10 — mTLS support (Option A) — None means use Option B (IP allowlist at service)
    compliance_api_ca_bundle: Path | None = None
    compliance_api_client_cert: Path | None = None
    compliance_api_client_key: Path | None = None

    # ─── OIDC (WI-02) ────────────────────────────────────────────────────────
    oidc_issuer: HttpUrl = Field(default=HttpUrl("https://auth.example.com/"))
    oidc_client_id: str = "compliance-portal"
    oidc_client_secret: SecretStr = SecretStr("dev-secret")
    oidc_redirect_uri: HttpUrl = Field(
        default=HttpUrl("http://localhost:8080/auth/callback")
    )
    oidc_discovery: bool = True

    # Group → role map
    oidc_group_admin: str = "compliance-portal-admin"
    oidc_group_compliance_officer: str = "compliance-portal-officer"
    oidc_group_auditor: str = "compliance-portal-auditor"
    oidc_group_sme: str = "compliance-portal-sme"
    oidc_group_viewer: str = "compliance-portal-viewer"

    # ─── Sessions ────────────────────────────────────────────────────────────
    session_secret: SecretStr = Field(
        default=SecretStr("development-only-secret-please-replace-32bytes!"),
    )
    session_max_age_s: int = 3600
    session_cookie_name: str = "cp_session"
    session_cookie_secure: bool = True
    session_cookie_httponly: bool = True
    session_cookie_samesite: Literal["lax", "strict", "none"] = "lax"

    redis_url: str | None = "redis://localhost:6379/0"

    # ─── PostgreSQL (read-only views) ────────────────────────────────────────
    pg_dsn: SecretStr | None = SecretStr(
        "postgresql+asyncpg://portal:portal@localhost:5432/compliance_portal"
    )

    # ─── Qdrant ──────────────────────────────────────────────────────────────
    qdrant_url: HttpUrl = Field(default=HttpUrl("http://localhost:6333"))
    qdrant_api_key: SecretStr | None = None

    # ─── Public DSR (WI-09 placeholders) ─────────────────────────────────────
    captcha_provider: str = "hcaptcha"
    captcha_site_key: str = ""
    captcha_secret: SecretStr = SecretStr("")
    public_rate_limit_per_min: int = 100

    # ─── Markdown proxy (WI-16) ──────────────────────────────────────────────
    markdown_proxy_url: HttpUrl | None = None

    # ─── Ed25519 signing (WI-12) ─────────────────────────────────────────────
    signing_key_id: str | None = None

    # ─── Trusted proxies (WI-17) ─────────────────────────────────────────────
    trusted_proxies: str = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12"

    # ─── CORS (WI-17) ────────────────────────────────────────────────────────
    cors_allowed_origins: str = "https://portal.internal"

    # ─── Behavioral hook (WI-17) ─────────────────────────────────────────────
    behavior_hook_enabled: bool = False
    behavior_hook_url: HttpUrl | None = None

    # ── Validators ───────────────────────────────────────────────────────────
    @field_validator("session_secret")
    @classmethod
    def _session_secret_strength(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("session_secret must be at least 32 characters")
        return v

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"invalid log_level: {v}")
        return v

    # ── Convenience accessors ────────────────────────────────────────────────
    @property
    def trusted_proxy_cidrs(self) -> list[str]:
        return [c.strip() for c in self.trusted_proxies.split(",") if c.strip()]

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def is_mtls_configured(self) -> bool:
        return bool(
            self.compliance_api_client_cert
            and self.compliance_api_client_key
            and self.compliance_api_ca_bundle
        )

    @property
    def role_to_group_map(self) -> dict[str, str]:
        """Returns {role_name: idp_group_name}."""
        return {
            "admin": self.oidc_group_admin,
            "compliance_officer": self.oidc_group_compliance_officer,
            "auditor": self.oidc_group_auditor,
            "sme": self.oidc_group_sme,
            "viewer": self.oidc_group_viewer,
        }

    @property
    def group_to_role_map(self) -> dict[str, str]:
        """Inverse: {idp_group_name: role_name}."""
        return {v: k for k, v in self.role_to_group_map.items()}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton — used by FastAPI deps and module-level code."""
    return Settings()


def reset_settings_cache() -> None:
    """Clear the cache. Used by tests that override env vars."""
    get_settings.cache_clear()
