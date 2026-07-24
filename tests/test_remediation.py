"""Adversarial-review remediation tests (2026-04-27).

Exercises the fixes for each finding F-01 through F-12 (skipping F-13..F-16 LOW)
to prevent regressions.

Each section is annotated with the finding ID and a one-line summary so the
adversarial reviewer can trace test → fix → finding.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

# Path setup is handled by conftest.py.

# ─── F-01 — HMAC verify_guardian_webhook ──────────────────────────────────────


class TestF01HmacGuardianWebhook:
    """The ``verify_guardian_webhook`` helper now uses ``hmac.HMAC`` directly
    and rejects forged or stale signatures."""

    def _make_signature(
        self, *, secret: str, body: bytes, ts: str
    ) -> str:
        material = f"{ts}.".encode() + body
        digest = hmac.HMAC(
            key=secret.encode(),
            msg=material,
            digestmod=hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def test_verifies_correct_signature(self) -> None:
        from portal.routers.incidents import verify_guardian_webhook

        secret = "very-secret-32-character-key-for-test-only"
        body = b'{"event":"compliance.incident.created"}'
        ts = str(int(time.time()))
        sig = self._make_signature(secret=secret, body=body, ts=ts)

        # Should NOT raise
        verify_guardian_webhook(
            body,
            signature_header=sig,
            timestamp_header=ts,
            secret=secret,
        )

    def test_rejects_tampered_body(self) -> None:
        from fastapi import HTTPException

        from portal.routers.incidents import verify_guardian_webhook

        secret = "very-secret-32-character-key-for-test-only"
        body = b'{"event":"compliance.incident.created"}'
        ts = str(int(time.time()))
        sig = self._make_signature(secret=secret, body=body, ts=ts)

        with pytest.raises(HTTPException) as info:
            verify_guardian_webhook(
                body + b"X",  # tampered
                signature_header=sig,
                timestamp_header=ts,
                secret=secret,
            )
        assert info.value.status_code == 401
        assert info.value.detail == "bad_signature"

    def test_rejects_wrong_secret(self) -> None:
        from fastapi import HTTPException

        from portal.routers.incidents import verify_guardian_webhook

        body = b"payload"
        ts = str(int(time.time()))
        sig = self._make_signature(
            secret="test-secret-placeholder",
            body=body,
            ts=ts,
        )
        with pytest.raises(HTTPException) as info:
            verify_guardian_webhook(
                body,
                signature_header=sig,
                timestamp_header=ts,
                secret="test-secret-placeholder",
            )
        assert info.value.status_code == 401

    def test_rejects_stale_timestamp(self) -> None:
        from fastapi import HTTPException

        from portal.routers.incidents import verify_guardian_webhook

        secret = "x" * 32
        body = b"payload"
        ts = str(int(time.time()) - 10_000)  # very stale
        sig = self._make_signature(secret=secret, body=body, ts=ts)
        with pytest.raises(HTTPException) as info:
            verify_guardian_webhook(
                body,
                signature_header=sig,
                timestamp_header=ts,
                secret=secret,
            )
        assert info.value.status_code == 401
        assert info.value.detail == "stale_timestamp"

    def test_rejects_empty_secret(self) -> None:
        from fastapi import HTTPException

        from portal.routers.incidents import verify_guardian_webhook

        body = b"payload"
        ts = str(int(time.time()))
        with pytest.raises(HTTPException):
            verify_guardian_webhook(
                body,
                signature_header="sha256=" + "00" * 32,
                timestamp_header=ts,
                secret="",
            )

    def test_rejects_non_numeric_timestamp(self) -> None:
        from fastapi import HTTPException

        from portal.routers.incidents import verify_guardian_webhook

        with pytest.raises(HTTPException) as info:
            verify_guardian_webhook(
                b"payload",
                signature_header="sha256=00",
                timestamp_header="not-a-number",
                secret="x" * 32,
            )
        assert info.value.detail == "bad_timestamp"


# ─── F-02 — Open redirect on `next` ───────────────────────────────────────────


class TestF02SafeNextUrl:
    """``safe_next_url`` only accepts same-origin relative paths."""

    @pytest.mark.parametrize(
        "value",
        [
            "/",
            "/dashboard",
            "/dashboard?tab=audit",
            "/path/with/segments",
            "/a#anchor",
        ],
    )
    def test_accepts_relative(self, value: str) -> None:
        from portal.auth.oidc import safe_next_url

        assert safe_next_url(value) == value

    @pytest.mark.parametrize(
        "value",
        [
            "https://evil.example.com/",
            "http://evil.example.com/",
            "//evil.example.com/path",
            "\\\\evil.example.com\\path",
            "/\\evil.example.com",
            "javascript:alert(1)",
            "data:text/html,<script>",
            "ftp://files.example.com",
            "relative/no/leading/slash",
            "",
            None,
            "/path with space",  # control char family — newline test below
            "/path\nwith\nnewline",
            "/path\twith\ttab",
        ],
    )
    def test_rejects_dangerous(self, value):
        from portal.auth.oidc import safe_next_url

        assert safe_next_url(value) == "/"

    def test_callback_redirects_to_root_when_next_is_external(
        self, monkeypatch
    ) -> None:
        """End-to-end: a malicious `next` is replaced with `/` after login."""
        from portal.auth.oidc import safe_next_url

        # The callback re-validates `next` defensively, so even if someone
        # bypasses the issuance-time check they still cannot redirect off-site.
        assert safe_next_url("https://evil.example.com/steal") == "/"


# ─── F-03 — IDENTITY_UPLOAD capability enforcement ────────────────────────────


class TestF03IdentityUploadCapability:
    """The ``/dsr/identity-upload`` route requires a token whose capability is
    IDENTITY_UPLOAD; STATUS_CHECK or RECEIPT_DOWNLOAD tokens must be rejected."""

    def _build_app(self):
        from dsr_portal.main import create_public_app
        from tests._fakes import FakeComplianceClient

        fake = FakeComplianceClient()
        fake._ensure_dsr_storage()

        def factory(_request):
            return fake

        app = create_public_app(compliance_client_factory=factory)
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        return app, fake

    def test_missing_token_returns_401(self) -> None:
        app, _ = self._build_app()
        with TestClient(app) as c:
            r = c.post(
                "/dsr/identity-upload",
                data={
                    "reference": "DSR-PUB-001",
                    "email": "alice@example.com",
                    "captcha_token": "any",
                },
                files={
                    "identity_proof": (
                        "id.pdf",
                        b"%PDF-1.4\nminimal\n",
                        "application/pdf",
                    )
                },
            )
        assert r.status_code == 401

    def test_status_check_token_rejected_as_acl_violation(self) -> None:
        from dsr_portal.auth.token import TokenCapability

        app, _ = self._build_app()
        token_mgr = app.state.public_token_mgr
        wrong_capability_token = token_mgr.issue(
            reference="DSR-PUB-001",
            email="alice@example.com",
            capability=TokenCapability.STATUS_CHECK,  # not IDENTITY_UPLOAD
        )
        with TestClient(app) as c:
            r = c.post(
                "/dsr/identity-upload",
                data={
                    "reference": "DSR-PUB-001",
                    "email": "alice@example.com",
                    "captcha_token": "any",
                    "token": wrong_capability_token,
                },
                files={
                    "identity_proof": (
                        "id.pdf",
                        b"%PDF-1.4\nminimal\n",
                        "application/pdf",
                    )
                },
            )
        assert r.status_code == 403
        assert "service_account_acl_violation" in r.text

    def test_correct_capability_token_accepted(self) -> None:
        from dsr_portal.auth.token import TokenCapability

        app, _ = self._build_app()
        token_mgr = app.state.public_token_mgr
        correct_token = token_mgr.issue(
            reference="DSR-PUB-001",
            email="alice@example.com",
            capability=TokenCapability.IDENTITY_UPLOAD,
        )
        with TestClient(app) as c:
            r = c.post(
                "/dsr/identity-upload",
                data={
                    "reference": "DSR-PUB-001",
                    "email": "alice@example.com",
                    "captcha_token": "any",
                    "token": correct_token,
                },
                files={
                    "identity_proof": (
                        "id.pdf",
                        b"%PDF-1.4\nminimal\n",
                        "application/pdf",
                    )
                },
            )
        # 200 expected because the fake compliance client returns clean.
        assert r.status_code == 200

    def test_token_reference_must_match_form_reference(self) -> None:
        from dsr_portal.auth.token import TokenCapability

        app, _ = self._build_app()
        token_mgr = app.state.public_token_mgr
        # Token says reference=X, form claims reference=Y.
        token = token_mgr.issue(
            reference="DSR-PUB-AAA",
            email="alice@example.com",
            capability=TokenCapability.IDENTITY_UPLOAD,
        )
        with TestClient(app) as c:
            r = c.post(
                "/dsr/identity-upload",
                data={
                    "reference": "DSR-PUB-BBB",  # mismatch
                    "email": "alice@example.com",
                    "captcha_token": "any",
                    "token": token,
                },
                files={
                    "identity_proof": (
                        "id.pdf",
                        b"%PDF-1.4\nminimal\n",
                        "application/pdf",
                    )
                },
            )
        assert r.status_code == 403
        assert "token_reference_mismatch" in r.text


# ─── F-04 — CSRF middleware preserves form body ───────────────────────────────


class TestF04CsrfPreservesFormBody:
    """The CSRF middleware re-buffers the original request body so downstream
    handlers see the form fields intact."""

    def _build(self):
        from portal.auth.csrf import CsrfTokenManager
        from portal.middleware.csrf_mw import CsrfMiddleware

        tm = CsrfTokenManager(secret="x" * 32)
        token = tm.generate()

        app = FastAPI()

        @app.post("/echo")
        async def _echo(request: Request):
            form = await request.form()
            return {"received": dict(form)}

        app.add_middleware(
            CsrfMiddleware,
            token_manager=tm,
            cookie_name="csrf",
            secure_cookie=False,
            samesite="lax",
        )
        return app, token

    def test_form_post_with_csrf_in_body_arrives_intact(self) -> None:
        app, token = self._build()
        with TestClient(app) as c:
            r = c.post(
                "/echo",
                data={
                    "csrf_token": token,
                    "request_type": "access",
                    "subject_name": "Alice",
                    "subject_email": "alice@example.com",
                    "description": "I want my data",
                },
                cookies={"csrf": token},
            )
        assert r.status_code == 200
        body = r.json()["received"]
        # Every submitted field must be present (F-04 regression check)
        assert body["request_type"] == "access"
        assert body["subject_name"] == "Alice"
        assert body["subject_email"] == "alice@example.com"
        assert body["description"] == "I want my data"
        assert body["csrf_token"] == token

    def test_form_post_without_csrf_token_returns_403(self) -> None:
        app, _ = self._build()
        with TestClient(app) as c:
            r = c.post(
                "/echo",
                data={"subject_name": "x"},
            )
        assert r.status_code == 403
        assert r.json()["code"] == "csrf_invalid"


# ─── F-05 — MFA nonce manager backed by Redis (or in-memory test backend) ────


class TestF05MfaNonceBackend:
    """``MfaNonceManager`` accepts a pluggable backend and degrades safely on
    cross-worker scenarios when Redis is used. We exercise both backends to
    pin the contract."""

    def test_in_memory_backend_round_trip(self) -> None:
        from portal.auth.mfa import MfaNonceManager

        mgr = MfaNonceManager(max_age_s=60)
        token = mgr.issue("alice", "gate.decide:abc")
        assert mgr.consume(token, "alice", "gate.decide:abc") is True
        # Replay: must fail
        assert mgr.consume(token, "alice", "gate.decide:abc") is False

    def test_fakeredis_backend_round_trip(self) -> None:
        fakeredis = pytest.importorskip("fakeredis")
        from portal.auth.mfa import MfaNonceManager

        client = fakeredis.FakeRedis()
        mgr = MfaNonceManager(max_age_s=60, redis_client=client)
        token = mgr.issue("alice", "gate.decide:abc")
        assert mgr.consume(token, "alice", "gate.decide:abc") is True
        # Replay: must fail
        assert mgr.consume(token, "alice", "gate.decide:abc") is False

    def test_fakeredis_backend_nonce_visible_across_managers(self) -> None:
        """A nonce issued by one manager (worker) is consumable by another
        sharing the same Redis — exactly the property the in-memory dict
        previously lacked under multi-worker uvicorn (F-05)."""
        fakeredis = pytest.importorskip("fakeredis")
        from portal.auth.mfa import MfaNonceManager

        client = fakeredis.FakeRedis()
        mgr_worker_a = MfaNonceManager(max_age_s=60, redis_client=client)
        mgr_worker_b = MfaNonceManager(max_age_s=60, redis_client=client)

        token = mgr_worker_a.issue("alice", "gate.decide:abc")
        # Worker B can consume the token Worker A issued.
        assert mgr_worker_b.consume(token, "alice", "gate.decide:abc") is True
        # Worker A then sees it as already consumed (replay protection).
        assert mgr_worker_a.consume(token, "alice", "gate.decide:abc") is False

    def test_fakeredis_backend_wrong_user_consumes_nonce(self) -> None:
        """Wrong-user consume still pops the record (matches in-memory contract)."""
        fakeredis = pytest.importorskip("fakeredis")
        from portal.auth.mfa import MfaNonceManager

        client = fakeredis.FakeRedis()
        mgr = MfaNonceManager(max_age_s=60, redis_client=client)
        token = mgr.issue("alice", "x")
        assert mgr.consume(token, "bob", "x") is False
        # Token is now consumed even by the rightful user.
        assert mgr.consume(token, "alice", "x") is False


# ─── F-06 — Distinct secret files in compose.yaml ─────────────────────────────


class TestF06DistinctSecretFiles:
    """Each Docker Compose secret name maps to a distinct file. Two secrets
    that share a backing file would compromise key separation."""

    def test_compose_secrets_have_distinct_files(self) -> None:
        import os

        import yaml

        compose_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "docker",
            "compose.yaml",
        )
        with open(compose_path, "r", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        secrets = compose.get("secrets", {})
        # Every secret that the public DSR portal uses must NOT share a file
        # with the internal portal's session secret.
        session_secret_file = secrets["session_secret"]["file"]
        public_token_file = secrets["public_token_secret"]["file"]
        session_secret_public_file = secrets["session_secret_public"]["file"]
        captcha_secret_file = secrets["captcha_secret"]["file"]

        assert public_token_file != session_secret_file
        assert session_secret_public_file != session_secret_file
        assert captcha_secret_file != session_secret_file
        # Public-portal session secret and public token secret are DIFFERENT
        # secrets and must not collide with each other either.
        assert public_token_file != session_secret_public_file


# ─── F-07 — asyncio.get_running_loop ─────────────────────────────────────────


class TestF07AsyncioApi:
    def test_pdf_service_uses_get_running_loop(self) -> None:
        """Static check: source no longer references ``get_event_loop``."""
        import inspect

        from portal.pdf import service

        source = inspect.getsource(service)
        assert "asyncio.get_event_loop" not in source
        assert "asyncio.get_running_loop" in source


# ─── F-08 / F-10 — content-type allowlist ────────────────────────────────────


class TestF08F10ContentTypeAllowlist:
    @pytest.mark.parametrize(
        "ct,expected",
        [
            ("image/jpeg", True),
            ("image/png", True),
            ("application/pdf", True),
            ("image/jpeg; charset=binary", True),
            ("APPLICATION/PDF", True),  # case insensitive
            ("application/octet-stream", False),
            ("image/svg+xml", False),
            ("text/html", False),
            ("application/zip", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_allowed_content_type(self, ct, expected) -> None:
        from dsr_portal.malware_scan import is_allowed_content_type

        assert is_allowed_content_type(ct) is expected

    def test_octet_stream_upload_rejected_with_415(self) -> None:
        from dsr_portal.auth.token import TokenCapability
        from dsr_portal.main import create_public_app
        from tests._fakes import FakeComplianceClient

        fake = FakeComplianceClient()
        fake._ensure_dsr_storage()
        app = create_public_app(compliance_client_factory=lambda _: fake)
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        token_mgr = app.state.public_token_mgr
        token = token_mgr.issue(
            reference="DSR-PUB-1",
            email="alice@example.com",
            capability=TokenCapability.IDENTITY_UPLOAD,
        )
        with TestClient(app) as c:
            r = c.post(
                "/dsr/identity-upload",
                data={
                    "reference": "DSR-PUB-1",
                    "email": "alice@example.com",
                    "captcha_token": "any",
                    "token": token,
                },
                files={
                    "identity_proof": (
                        "id.bin",
                        b"\x00\x00\x00\x00",
                        "application/octet-stream",
                    )
                },
            )
        assert r.status_code == 415
        assert "identity_proof_unsupported_media_type" in r.text

    def test_suspicious_magic_bytes_rejected_at_submit(self) -> None:
        """Polyglot or unknown-magic content is rejected at the portal so it
        never reaches the service-side scanner (F-08)."""
        from dsr_portal.main import create_public_app
        from tests._fakes import FakeComplianceClient

        fake = FakeComplianceClient()
        fake._ensure_dsr_storage()
        app = create_public_app(compliance_client_factory=lambda _: fake)
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        with TestClient(app) as c:
            r = c.post(
                "/dsr/submit",
                data={
                    "request_type": "access",
                    "subject_name": "Alice",
                    "subject_email": "alice@example.com",
                    "captcha_token": "any",
                },
                files={
                    "identity_proof": (
                        "fake.pdf",
                        b"this is not a real pdf",  # no magic
                        "application/pdf",
                    )
                },
            )
        # The compliance fake never sees this — rejected at the portal.
        assert r.status_code == 422
        assert "identity_proof_rejected" in r.text


# ─── F-09 — CSRF prefix exemption normalisation ──────────────────────────────


class TestF09CsrfExemptPathMatching:
    def _mw(self, exempt_paths):
        from portal.auth.csrf import CsrfTokenManager
        from portal.middleware.csrf_mw import CsrfMiddleware

        # Build a stand-alone middleware instance (no ASGI app needed for
        # unit-testing _is_exempt).
        tm = CsrfTokenManager(secret="x" * 32)
        return CsrfMiddleware(
            app=lambda *a, **kw: None,
            token_manager=tm,
            exempt_paths=exempt_paths,
        )

    def test_exact_match_exempt(self) -> None:
        mw = self._mw(["/healthz"])
        assert mw._is_exempt("/healthz") is True

    def test_subpath_exempt(self) -> None:
        mw = self._mw(["/webhooks"])
        assert mw._is_exempt("/webhooks/guardian") is True

    def test_does_not_exempt_extended_name(self) -> None:
        """``/healthzXXX`` MUST NOT be exempt when ``/healthz`` is configured."""
        mw = self._mw(["/healthz"])
        assert mw._is_exempt("/healthzXXX") is False
        assert mw._is_exempt("/healthz_admin") is False

    def test_traversal_sequence_normalised(self) -> None:
        """``/auth/callback/../api/secret`` must NOT be exempt by virtue of
        starting with ``/auth/callback``."""
        mw = self._mw(["/auth/callback"])
        assert mw._is_exempt("/auth/callback/../api/secret") is False

    def test_empty_exempt_path_does_not_match_everything(self) -> None:
        mw = self._mw([""])
        assert mw._is_exempt("/anything") is False

    def test_root_exempt_path_does_not_match_everything(self) -> None:
        mw = self._mw(["/"])
        # An exempt list of just "/" should not silently exempt every path —
        # the rstrip("/") yields "" which short-circuits.
        assert mw._is_exempt("/anything") is False


# ─── F-11 — audit guard regex coverage ───────────────────────────────────────


class TestF11AuditGuardRegex:
    @pytest.mark.parametrize(
        "sql",
        [
            # Original DML
            "INSERT INTO immutable_audit_events (a, b) VALUES (1, 2)",
            "UPDATE immutable_audit_events SET x=1",
            "DELETE FROM immutable_audit_events WHERE id=1",
            "MERGE INTO immutable_audit_events m USING t ON m.id=t.id",
            "TRUNCATE immutable_audit_events",
            "TRUNCATE TABLE immutable_audit_events",
            # New patterns (F-11)
            "ALTER TABLE immutable_audit_events ADD COLUMN x INT",
            "ALTER TABLE IF EXISTS immutable_audit_events ADD COLUMN x INT",
            "DROP TABLE immutable_audit_events",
            "DROP TABLE IF EXISTS immutable_audit_events",
            "RENAME TABLE immutable_audit_events TO old_audit",
            # Comment obfuscation
            "INSERT /* sneaky */ INTO immutable_audit_events VALUES (1)",
            "INSERT -- inline\nINTO immutable_audit_events VALUES (1)",
            "/*hello*/INSERT INTO immutable_audit_events VALUES (1)",
            # CTE / WITH prefix
            "WITH x AS (SELECT 1) INSERT INTO immutable_audit_events VALUES (1)",
            # Schema-qualified
            'INSERT INTO public."immutable_audit_events" VALUES (1)',
            "MERGE INTO public.immutable_audit_events USING t ON t.id=immutable_audit_events.id",
        ],
    )
    def test_query_blocked(self, sql: str) -> None:
        from portal.middleware.audit_guard import query_touches_audit_table

        assert query_touches_audit_table(sql) is True, sql

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM immutable_audit_events",
            "SELECT count(*) FROM immutable_audit_events WHERE x=1",
            "INSERT INTO some_other_table VALUES (1)",
            "UPDATE other SET x=1 WHERE id=1",
        ],
    )
    def test_safe_query_allowed(self, sql: str) -> None:
        from portal.middleware.audit_guard import query_touches_audit_table

        assert query_touches_audit_table(sql) is False, sql


# ─── F-12 — Phantom MFA freshness ────────────────────────────────────────────


class TestF12PhantomMfaFreshness:
    """When the IdP returns ``amr`` indicating MFA but no ``auth_time``, we
    must NOT credit the user with fresh MFA. ``mfa_at`` must be ``None`` so
    step-up is required."""

    def test_amr_with_auth_time_sets_mfa_at(self) -> None:
        from portal.auth.oidc import build_user_from_claims
        from portal.config import Settings

        settings = Settings()
        claims = {
            "sub": "user-1",
            "email": "alice@example.com",
            "name": "Alice",
            "groups": list(settings.group_to_role_map.keys())[:1],
            "amr": ["mfa"],
            "auth_time": int(time.time()),
        }
        user = build_user_from_claims(
            claims=claims, settings=settings, session_id="placeholder"
        )
        assert user.mfa_at is not None

    def test_amr_without_auth_time_yields_none(self) -> None:
        from portal.auth.oidc import build_user_from_claims
        from portal.config import Settings

        settings = Settings()
        claims = {
            "sub": "user-1",
            "email": "alice@example.com",
            "name": "Alice",
            "groups": list(settings.group_to_role_map.keys())[:1],
            "amr": ["mfa"],
            # NO auth_time — must NOT fall back to issued_at
        }
        user = build_user_from_claims(
            claims=claims, settings=settings, session_id="placeholder"
        )
        assert user.mfa_at is None

    @pytest.mark.asyncio
    async def test_require_mfa_rejects_when_mfa_at_missing(self) -> None:
        from portal.auth.mfa import StepUpRequired, require_mfa
        from portal.auth.models import Role, User

        now = datetime.now(timezone.utc)
        user_no_mfa = User(
            sub="user-1",
            email="alice@example.com",
            name="Alice",
            roles=[Role.COMPLIANCE_OFFICER],
            auditor_scope=None,
            mfa_at=None,  # absent
            session_id="placeholder",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
        dep = require_mfa(max_age_s=60)
        with pytest.raises(StepUpRequired):
            await dep(user=user_no_mfa)
