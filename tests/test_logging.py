"""Logging / PII redaction tests (AMD-17).

These tests exercise the `_redact_pii` processor directly so they don't
mutate global structlog config (and therefore don't interfere with other
test modules that rely on the production config).
"""

from __future__ import annotations

from portal.logging import (
    REDACTED_FIELDS,
    REDACTED_VALUE,
    _redact_pii,
    configure_logging,
    get_logger,
)


def _redact(event_dict: dict) -> dict:
    """Apply the redaction processor in isolation."""
    return _redact_pii(None, "info", dict(event_dict))


def test_redacts_subject_email() -> None:
    out = _redact({"event": "dsr.received", "subject_email": "alice@example.com", "request_id": "r1"})
    assert out["subject_email"] == REDACTED_VALUE
    assert out["request_id"] == "r1"


def test_redacts_all_amd17_pii_fields() -> None:
    pii = {
        "subject_email": "x@y.com",
        "subject_name": "Jane Doe",
        "subject_phone": "+1-555-0100",
        "subject_address": "1 Main St",
        "dob": "1990-01-01",
    }
    out = _redact({"event": "dsr.full", **pii})
    for k in pii:
        assert out[k] == REDACTED_VALUE


def test_redaction_is_recursive() -> None:
    out = _redact({
        "event": "dsr.nested",
        "submission": {"subject": {"subject_email": "deep@example.com", "id": "abc"}},
    })
    assert out["submission"]["subject"]["subject_email"] == REDACTED_VALUE
    assert out["submission"]["subject"]["id"] == "abc"


def test_redaction_walks_lists() -> None:
    out = _redact({
        "event": "dsr.batch",
        "subjects": [
            {"subject_email": "a@x", "id": 1},
            {"subject_email": "b@x", "id": 2},
        ],
    })
    assert out["subjects"][0]["subject_email"] == REDACTED_VALUE
    assert out["subjects"][1]["subject_email"] == REDACTED_VALUE
    assert out["subjects"][0]["id"] == 1


def test_redacts_secrets_too() -> None:
    out = _redact({"event": "auth.token", "token": "secret-bearer-xyz", "authorization": "Bearer xyz"})
    assert out["token"] == REDACTED_VALUE
    assert out["authorization"] == REDACTED_VALUE


def test_redaction_is_case_insensitive() -> None:
    out = _redact({"Subject_Email": "a@b", "DOB": "2000-01-01", "SUBJECT_NAME": "x"})
    assert out["Subject_Email"] == REDACTED_VALUE
    assert out["DOB"] == REDACTED_VALUE
    assert out["SUBJECT_NAME"] == REDACTED_VALUE


def test_redaction_passes_through_non_redacted_fields() -> None:
    out = _redact({"event": "ok", "user_id": "alice", "action": "view"})
    assert out["user_id"] == "alice"
    assert out["action"] == "view"


def test_redacted_fields_includes_amd17_set() -> None:
    """Static check: REDACTED_FIELDS includes the AMD-17 PII fields."""
    required = {"subject_email", "subject_name", "subject_phone", "subject_address", "dob"}
    assert required.issubset(REDACTED_FIELDS)


def test_configure_logging_does_not_crash() -> None:
    configure_logging(level="DEBUG", json_output=True)
    log = get_logger("test")
    log.info("ok")
