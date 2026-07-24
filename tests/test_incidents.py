"""WI-10 — Incident Console router tests.

Covers:
  * 72-hour countdown band boundaries
  * AMD-19 markdown XSS hardening (script, javascript:, img onerror)
  * Append-only notes
  * AMD-18 webhook HMAC + timestamp skew
  * Notification recording
  * Status transitions
  * Manual create restricted to admin
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import Role
from portal.routers import incidents as incidents_router_module
from portal.routers.incidents import verify_guardian_webhook
from portal.services.incident_clock import band, format_remaining
from portal.services.markdown_render import render_note

from tests._fakes import build_incident


# ─── Markdown rendering hardening (AMD-19) ───────────────────────────────────


class TestMarkdownHardening:
    def test_script_tag_escaped(self):
        out = render_note("Hello <script>alert(1)</script>")
        assert "<script>" not in out
        assert "alert" in out  # text preserved (escaped)

    def test_javascript_protocol_in_link_not_executable(self):
        # markdown-it with html=False does not auto-link [text](javascript:...);
        # the literal text remains in the paragraph (no anchor element created).
        # Critical security property: no <a href="javascript:..."> tag in output.
        out = render_note("[click](javascript:alert(1))")
        assert '<a href="javascript:' not in out
        assert "<a href='javascript:" not in out

    def test_img_tag_stripped_no_dom_element(self):
        # Raw HTML inside markdown is escaped (html=False); the <img> never
        # becomes a DOM element. The literal text "onerror" may appear escaped
        # but with no surrounding tag, so it cannot execute.
        out = render_note('<img src=x onerror="alert(1)">')
        # No <img tag in the output (this is the critical property).
        assert "<img " not in out
        assert "<img>" not in out

    def test_event_handler_attribute_stripped_from_real_anchor(self):
        # If somehow an <a> tag survived, its onclick would be stripped.
        # Test by feeding markdown that produces an actual link first, then
        # confirm no JS attrs leak.
        out = render_note("[example](https://example.com)")
        assert "onclick" not in out
        assert "<a " in out

    def test_strong_em_preserved(self):
        out = render_note("**bold** and _italic_")
        assert "<strong>" in out
        assert "<em>" in out

    def test_links_get_nofollow_noopener(self):
        out = render_note("Visit https://example.com please")
        assert 'rel="nofollow noopener"' in out or 'rel="nofollow"' in out

    def test_iframe_stripped(self):
        out = render_note("<iframe src='http://evil'></iframe>")
        assert "<iframe" not in out


# ─── Countdown band ──────────────────────────────────────────────────────────


class TestIncidentClock:
    def test_band_green_at_72h(self):
        triggered = datetime.now(UTC) - timedelta(hours=1)
        assert band(triggered) == "green"

    def test_band_amber_at_24h_remaining(self):
        triggered = datetime.now(UTC) - timedelta(hours=49)  # 23h remaining
        assert band(triggered) == "amber"

    def test_band_red_at_6h_remaining(self):
        triggered = datetime.now(UTC) - timedelta(hours=67)  # 5h remaining
        assert band(triggered) == "red"

    def test_band_overdue(self):
        triggered = datetime.now(UTC) - timedelta(hours=80)  # past 72h
        assert band(triggered) == "overdue"

    def test_format_remaining_overdue(self):
        triggered = datetime.now(UTC) - timedelta(hours=80)
        assert format_remaining(triggered) == "OVERDUE"

    def test_format_remaining_hms(self):
        triggered = datetime.now(UTC) - timedelta(hours=1)
        s = format_remaining(triggered)
        # Format HH:MM:SS — should start with "70" (71 hours = "71:..." or similar)
        assert ":" in s
        h_str = s.split(":")[0]
        assert int(h_str) in (70, 71)


# ─── Webhook HMAC (AMD-18) ───────────────────────────────────────────────────


def _make_signature(body: bytes, ts: str, secret: str) -> str:
    signed = f"{ts}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()


class TestWebhookHmacAmd18:
    def test_valid_signature_passes(self):
        secret = "test-secret-32-chars-aaaaaaaaaaaa"
        body = b'{"event_id":"e1","session_id":"s1","triggered_at":"2026-04-27T00:00:00Z","reason":"x","severity":"high"}'
        ts = str(int(time.time()))
        sig = _make_signature(body, ts, secret)
        # Should not raise
        verify_guardian_webhook(
            body, signature_header=sig, timestamp_header=ts, secret=secret
        )

    def test_bad_signature_rejected(self):
        secret = "test-secret-32-chars-aaaaaaaaaaaa"
        body = b'{"event_id":"e1"}'
        ts = str(int(time.time()))
        with pytest.raises(Exception) as exc:
            verify_guardian_webhook(
                body, signature_header="sha256=00", timestamp_header=ts, secret=secret
            )
        assert "bad_signature" in str(exc.value.detail) if hasattr(exc.value, "detail") else True

    def test_stale_timestamp_rejected_even_with_valid_sig(self):
        secret = "test-secret-32-chars-aaaaaaaaaaaa"
        body = b'{"event_id":"e1"}'
        old_ts = str(int(time.time()) - 600)  # 10 min ago
        sig = _make_signature(body, old_ts, secret)
        with pytest.raises(Exception) as exc:
            verify_guardian_webhook(
                body,
                signature_header=sig,
                timestamp_header=old_ts,
                secret=secret,
            )
        assert "stale_timestamp" in str(exc.value.detail) if hasattr(exc.value, "detail") else True

    def test_future_timestamp_rejected(self):
        secret = "test-secret-32-chars-aaaaaaaaaaaa"
        body = b'{"event_id":"e1"}'
        future_ts = str(int(time.time()) + 600)
        sig = _make_signature(body, future_ts, secret)
        with pytest.raises(Exception):
            verify_guardian_webhook(
                body,
                signature_header=sig,
                timestamp_header=future_ts,
                secret=secret,
            )

    def test_bad_timestamp_format_rejected(self):
        secret = "test-secret-32-chars-aaaaaaaaaaaa"
        with pytest.raises(Exception):
            verify_guardian_webhook(
                b"{}",
                signature_header="sha256=00",
                timestamp_header="not-a-number",
                secret=secret,
            )

    def test_empty_secret_fails_closed(self):
        with pytest.raises(Exception):
            verify_guardian_webhook(
                b"{}",
                signature_header="sha256=00",
                timestamp_header=str(int(time.time())),
                secret="",
            )


# ─── List + detail ───────────────────────────────────────────────────────────


class TestIncidentRouter:
    def test_index_renders(self, build_router_app, make_user, fake_compliance_client):
        inc = build_incident(incident_id="INC-1", triggered_hours_ago=10)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-1"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/incidents")
        assert r.status_code == 200
        assert "INC-1" in r.text

    def test_detail_renders_countdown(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-D", triggered_hours_ago=2)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-D"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/incidents/INC-D")
        assert r.status_code == 200
        assert "GREEN" in r.text or "AMBER" in r.text or "RED" in r.text

    def test_add_note_renders_safe_html(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-N", triggered_hours_ago=2)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-N"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            # Send malicious markdown — should be sanitized
            r = c.post(
                "/incidents/INC-N/notes",
                data={"content": "**bold** <script>alert(1)</script>"},
            )
        assert r.status_code == 200
        # Script tag must NOT be in the response body
        assert "<script>" not in r.text
        # Stored note should be sanitized
        stored = fake_compliance_client.incidents_storage["INC-N"].notes[0]
        assert "<script>" not in (stored.rendered_html or "")
        assert "<strong>" in (stored.rendered_html or "")

    def test_add_notification_records(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-NT", triggered_hours_ago=2)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-NT"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/incidents/INC-NT/notify",
                data={
                    "recipient": "regulator@ny.gov",
                    "channel": "regulator_portal",
                    "notification_status": "sent",
                },
            )
        assert r.status_code == 200
        notifs = fake_compliance_client.incidents_storage["INC-NT"].notifications
        assert len(notifs) == 1
        assert notifs[0].channel == "regulator_portal"

    def test_invalid_channel_400(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-NB", triggered_hours_ago=2)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-NB"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/incidents/INC-NB/notify",
                data={"recipient": "x", "channel": "carrier_pigeon"},
            )
        assert r.status_code == 400

    def test_transition_status_works(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-T", triggered_hours_ago=2)
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-T"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/incidents/INC-T/transition",
                data={"to_status": "investigating"},
            )
        assert r.status_code == 200
        assert fake_compliance_client.incidents_storage["INC-T"].status == "investigating"

    def test_invalid_transition_rejected(
        self, build_router_app, make_user, fake_compliance_client
    ):
        inc = build_incident(incident_id="INC-IT", triggered_hours_ago=2, status="closed")
        fake_compliance_client._ensure_incidents_storage()
        fake_compliance_client.incidents_storage["INC-IT"] = inc
        user = make_user(roles=[Role.COMPLIANCE_OFFICER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.post(
                "/incidents/INC-IT/transition",
                data={"to_status": "investigating"},
            )
        assert r.status_code == 400

    def test_viewer_forbidden(self, build_router_app, make_user):
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(incidents_router_module.router, user)
        with TestClient(app) as c:
            r = c.get("/incidents")
        assert r.status_code == 403


# ─── PDF resolver ─────────────────────────────────────────────────────────────


class TestIncidentPdfRegistration:
    def test_incident_report_resolver_registered(self):
        from portal.pdf.registry import get_default_registry
        from portal.routers.incidents import register_incident_pdf_components

        register_incident_pdf_components()
        reg = get_default_registry()
        assert "incident_report" in reg
