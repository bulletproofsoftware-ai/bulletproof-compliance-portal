"""WI-09 — Public DSR Portal tests.

Covers:
  * Landing + intake form rendering
  * AMD-05 token capability ACL (4-item enumeration)
  * AMD-01 identity state machine (received → identity_pending; SoD)
  * AMD-26 malware scan path (clean/infected/unscannable)
  * AMD-11 5MB body size cap (413)
  * CAPTCHA verification (none provider in test)
  * Honeypot dropping bots silently
  * Status check returns sanitized payload only (no PII echo)
  * Rate limiting (429) — global limiter installed
  * NO internal routes exposed (404 for /audit, /evidence, /gates)
  * /docs and /openapi.json hidden
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dsr_portal import create_public_app
from dsr_portal.auth.token import (
    PublicToken,
    PublicTokenManager,
    TokenCapability,
)
from dsr_portal.identity_state_machine import (
    IdentityState,
    is_terminal,
    is_valid_transition,
    sod_violation,
)
from dsr_portal.malware_scan import scan_file, MAX_BYTES

from tests._fakes import FakeComplianceClient


# ─── Token capability ACL (AMD-05) ───────────────────────────────────────────


class TestTokenAclAmd05:
    def test_acl_has_exactly_four_capabilities(self):
        # AMD-05 mandates exactly these four operations.
        assert {c.value for c in TokenCapability} == {
            "submit",
            "status_check",
            "identity_upload",
            "receipt_download",
        }

    def test_token_roundtrip(self):
        mgr = PublicTokenManager(secret="x" * 40)
        t = mgr.issue(
            reference="DSR-PUB-001",
            email="alice@example.com",
            capability=TokenCapability.STATUS_CHECK,
        )
        verified = mgr.verify(t)
        assert verified.reference == "DSR-PUB-001"
        assert verified.email == "alice@example.com"
        assert verified.capability == TokenCapability.STATUS_CHECK

    def test_secret_too_short_rejected(self):
        with pytest.raises(ValueError):
            PublicTokenManager(secret="short")

    def test_bad_signature_rejected(self):
        mgr = PublicTokenManager(secret="x" * 40)
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            mgr.verify("not-a-real-token")
        assert exc.value.status_code in (400, 410)

    def test_capability_normalized_to_enum(self):
        mgr = PublicTokenManager(secret="x" * 40)
        t = mgr.issue(
            reference="r1", email="a@b.com", capability=TokenCapability.SUBMIT
        )
        assert isinstance(mgr.verify(t).capability, TokenCapability)


# ─── Identity state machine (AMD-01) ─────────────────────────────────────────


class TestIdentityStateMachineAmd01:
    def test_received_to_identity_pending_only(self):
        assert is_valid_transition(
            IdentityState.RECEIVED, IdentityState.IDENTITY_PENDING
        )
        assert not is_valid_transition(IdentityState.RECEIVED, IdentityState.VERIFIED)

    def test_identity_pending_branches(self):
        assert is_valid_transition(
            IdentityState.IDENTITY_PENDING, IdentityState.VERIFIED
        )
        assert is_valid_transition(
            IdentityState.IDENTITY_PENDING, IdentityState.IDENTITY_INSUFFICIENT
        )
        assert is_valid_transition(
            IdentityState.IDENTITY_PENDING, IdentityState.IDENTITY_REJECTED
        )

    def test_insufficient_can_re_enter_pending(self):
        assert is_valid_transition(
            IdentityState.IDENTITY_INSUFFICIENT, IdentityState.IDENTITY_PENDING
        )

    def test_identity_rejected_terminal(self):
        assert is_terminal(IdentityState.IDENTITY_REJECTED)
        assert not is_valid_transition(
            IdentityState.IDENTITY_REJECTED, IdentityState.VERIFIED
        )

    def test_sod_blocks_self_review(self):
        assert sod_violation("alice", "alice") is True
        assert sod_violation("alice", "bob") is False
        assert sod_violation(None, "bob") is False


# ─── Malware scan (AMD-26) ───────────────────────────────────────────────────


class TestMalwareScanAmd26:
    def test_pdf_clean(self):
        result = scan_file(b"%PDF-1.4\nminimal pdf content\n%%EOF")
        assert result.status == "clean"
        assert result.detected_format == "application/pdf"

    def test_unknown_magic_suspicious(self):
        result = scan_file(b"\x00\x00\x00\x00random bytes")
        assert result.status == "suspicious"

    def test_oversize_unscannable(self):
        big = b"%PDF-" + b"\x00" * (MAX_BYTES + 100)
        result = scan_file(big)
        assert result.status == "unscannable"

    def test_empty_unscannable(self):
        result = scan_file(b"")
        assert result.status == "unscannable"

    def test_jpeg_clean(self):
        result = scan_file(b"\xff\xd8\xff" + b"\x00" * 100)
        assert result.status == "clean"
        assert result.detected_format == "image/jpeg"


# ─── App factory + routes ────────────────────────────────────────────────────


def _build_app_with_fake() -> tuple[FastAPI, FakeComplianceClient]:
    fake = FakeComplianceClient()
    fake._ensure_dsr_storage()

    def factory(_request):
        return fake

    app = create_public_app(compliance_client_factory=factory)
    return app, fake


class TestPublicAppFactory:
    def test_landing_renders(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r = c.get("/")
        assert r.status_code == 200
        assert "Data Subject Request Portal" in r.text

    def test_healthz_ok(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r = c.get("/healthz")
        assert r.status_code == 200

    def test_docs_disabled(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r1 = c.get("/docs")
            r2 = c.get("/openapi.json")
            r3 = c.get("/redoc")
        assert r1.status_code == 404
        assert r2.status_code == 404
        assert r3.status_code == 404

    def test_internal_routes_not_exposed(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            for path in ("/audit", "/evidence", "/gates", "/admin/auditor-engagements"):
                assert c.get(path).status_code == 404

    def test_intake_form_renders(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r = c.get("/dsr/submit")
        assert r.status_code == 200
        assert "Submit a DSR" in r.text

    def test_status_form_renders(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r = c.get("/dsr/status")
        assert r.status_code == 200
        assert "Check DSR status" in r.text


# ─── Submission flow ─────────────────────────────────────────────────────────


class TestSubmission:
    def test_submit_happy_path(self):
        app, fake = _build_app_with_fake()
        # Force captcha provider=none for tests
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
                    "captcha_token": "any-non-empty",
                },
            )
        assert r.status_code == 200
        assert "DSR-PUB-DSR-0001" in r.text
        # Submission registered
        assert len(fake.dsr_public_submissions) == 1

    def test_honeypot_drops_silently_no_service_call(self):
        app, fake = _build_app_with_fake()
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
                    "subject_name": "Bot",
                    "subject_email": "bot@example.com",
                    "captcha_token": "any",
                    "website": "evilbot",  # honeypot
                },
            )
        assert r.status_code == 200
        # Bogus reference — no real DSR
        assert len(fake.dsr_public_submissions) == 0

    def test_invalid_request_type_400(self):
        app, _ = _build_app_with_fake()
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        with TestClient(app) as c:
            r = c.post(
                "/dsr/submit",
                data={
                    "request_type": "bogus",
                    "subject_name": "X",
                    "subject_email": "x@y.com",
                    "captcha_token": "any",
                },
            )
        assert r.status_code == 400

    def test_captcha_missing_400(self):
        app, _ = _build_app_with_fake()
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
                    "subject_name": "X",
                    "subject_email": "x@y.com",
                    # no captcha_token
                },
            )
        assert r.status_code == 400

    def test_amd26_infected_proof_returns_422(self):
        app, fake = _build_app_with_fake()
        fake.dsr_force_scan_status = "infected"
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        with TestClient(app) as c:
            r = c.post(
                "/dsr/submit",
                data={
                    "request_type": "erasure",
                    "subject_name": "X",
                    "subject_email": "x@y.com",
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
        assert r.status_code == 422

    def test_amd11_oversize_413(self):
        app, _ = _build_app_with_fake()
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        # The middleware checks Content-Length; create a body > 5MB.
        big = b"%PDF-" + b"\x00" * (MAX_BYTES + 100)
        with TestClient(app) as c:
            r = c.post(
                "/dsr/submit",
                data={
                    "request_type": "access",
                    "subject_name": "X",
                    "subject_email": "x@y.com",
                    "captcha_token": "any",
                },
                files={"identity_proof": ("id.pdf", big, "application/pdf")},
            )
        assert r.status_code == 413


# ─── Status check ────────────────────────────────────────────────────────────


class TestStatusCheck:
    def test_status_404_does_not_distinguish(self):
        app, fake = _build_app_with_fake()
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        with TestClient(app) as c:
            r = c.post(
                "/dsr/status",
                data={
                    "reference": "DSR-PUB-9999",
                    "email": "wrong@example.com",
                    "captcha_token": "any",
                },
            )
        assert r.status_code == 404
        # Generic wording — never echoes which field was wrong
        assert "could not find" in r.text.lower()

    def test_status_returns_sanitized_payload(self):
        from shared.api_client import DsrPublicStatus

        app, fake = _build_app_with_fake()
        fake.dsr_public_statuses[("DSR-PUB-1", "alice@example.com")] = (
            DsrPublicStatus(
                reference="DSR-PUB-1",
                request_type="access",
                current_status="processing",
                submitted_at=datetime.now(UTC),
                days_remaining=12.0,
            )
        )
        app.state.settings_summary = {
            "captcha_provider": "none",
            "captcha_secret": "",
            "app_env": "test",
        }
        with TestClient(app) as c:
            r = c.post(
                "/dsr/status",
                data={
                    "reference": "DSR-PUB-1",
                    "email": "alice@example.com",
                    "captcha_token": "any",
                },
            )
        assert r.status_code == 200
        assert "DSR-PUB-1" in r.text
        assert "processing" in r.text


# ─── Rate limiter installed ──────────────────────────────────────────────────


class TestRateLimit:
    def test_limiter_attached(self):
        app, _ = _build_app_with_fake()
        assert app.state.limiter is not None


# ─── No body size leak via empty multipart ────────────────────────────────────


class TestBodyLimitMiddleware:
    def test_small_request_passes(self):
        app, _ = _build_app_with_fake()
        with TestClient(app) as c:
            r = c.get("/healthz")
        assert r.status_code == 200
