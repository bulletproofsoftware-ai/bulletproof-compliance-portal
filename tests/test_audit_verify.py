"""Audit hash-chain verify panel — no false integrity alert for unchained events.

Events reconstructed from the governance audit DB have no chain hash
(chain_index/chain_hash/prev_hash all None). The client-side recomputation must
not compare against a null hash (which always MISMATCHes) and raise a false
INTEGRITY ALERT against the service's trivial PASS.
"""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from portal.auth.models import Role
from shared.api_client.models import AuditEvent


def _app(build_router_app, make_user):
    from portal.routers import audit as m
    return build_router_app(m.router, make_user(roles=[Role.ADMIN]))


def test_unchained_event_shows_na_and_no_false_alert(build_router_app, fake_compliance_client, make_user):
    fake_compliance_client.audit_events = [
        AuditEvent(event_id="u1", audit_type="policy_check", user_id="system",
                   classification="restricted", ts=datetime.now(UTC),
                   chain_index=None, chain_hash=None, prev_hash=None,
                   payload={"conductor_tier": "STANDARD"})
    ]
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/audit/verify/u1")
    assert r.status_code == 200
    # neutral N/A state for an unchained event
    assert "not part of the portal hash chain" in r.text.lower()
    # no false-alert machinery rendered
    assert "integrity-alert" not in r.text
    assert "verify-data-u1" not in r.text
    # and it must NOT assert a misleading service "PASS" on a non-chained event
    assert ">PASS<" not in r.text


def test_chained_event_still_runs_recompute(build_router_app, fake_compliance_client, make_user):
    fake_compliance_client.audit_events = [
        AuditEvent(event_id="c1", audit_type="gate.decided", user_id="u1",
                   classification="internal", ts=datetime.now(UTC),
                   chain_index=5, chain_hash="abc123", prev_hash="def456",
                   payload={"x": 1})
    ]
    with TestClient(_app(build_router_app, make_user)) as client:
        r = client.get("/audit/verify/c1")
    assert r.status_code == 200
    assert "verify-data-c1" in r.text         # client recompute script present
    assert "integrity-alert" in r.text        # banner markup present (hidden until disagree)
    assert "abc123" in r.text                  # expected_hash embedded for comparison
