"""CAPTCHA verification for the public DSR portal.

Two providers supported:
    - hcaptcha (production)
    - none     (test / development only)

Production deployment MUST set `captcha_provider=hcaptcha` and a real
`captcha_secret`. The `none` provider is rejected if `app_env=production`.
"""

from __future__ import annotations

import httpx
from pydantic import BaseModel


class CaptchaResult(BaseModel):
    success: bool
    provider: str
    error: str | None = None


async def verify_captcha(
    *,
    token: str,
    remote_ip: str,
    provider: str,
    secret: str,
    app_env: str,
    site_verify_url: str = "https://hcaptcha.com/siteverify",
    timeout_s: float = 5.0,
) -> CaptchaResult:
    if not token:
        return CaptchaResult(success=False, provider=provider, error="missing_token")

    if provider == "none":
        if app_env == "production":
            return CaptchaResult(
                success=False, provider=provider, error="provider_none_forbidden_in_prod"
            )
        # Dev/test bypass — accept any non-empty token.
        return CaptchaResult(success=True, provider="none")

    if provider != "hcaptcha":
        return CaptchaResult(
            success=False, provider=provider, error="unknown_provider"
        )

    if not secret:
        return CaptchaResult(
            success=False, provider=provider, error="missing_secret"
        )

    async with httpx.AsyncClient(
        timeout=timeout_s,
        follow_redirects=False,
    ) as c:
        try:
            r = await c.post(
                site_verify_url,
                data={"secret": secret, "response": token, "remoteip": remote_ip},
            )
        except httpx.HTTPError as exc:
            return CaptchaResult(
                success=False, provider=provider, error=f"transport_error: {exc}"
            )
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        return CaptchaResult(success=False, provider=provider, error="bad_response")
    return CaptchaResult(
        success=bool(body.get("success", False)),
        provider=provider,
        error=None if body.get("success") else "captcha_rejected",
    )


__all__ = ["CaptchaResult", "verify_captcha"]
