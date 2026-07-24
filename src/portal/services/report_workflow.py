"""Regulatory report 5-stage workflow validation (REQ-CPL-026).

Pure-function state machine; the compliance service enforces authoritatively.
This is a portal-side pre-check / UI affordance.
"""

from __future__ import annotations

from typing import Final

VALID_REPORT_TYPES: Final[set[str]] = {
    "sox_attestation",
    "nydfs_part500",
    "eu_ai_act_conformity",
    "naic_adverse_action",
}

VALID_STAGES: Final[tuple[str, ...]] = (
    "draft",
    "review",
    "approved",
    "signed",
    "delivered",
)

# Allowed forward transitions; service is authoritative.
_VALID_TRANSITIONS: Final[dict[str, set[str]]] = {
    "draft": {"review"},
    "review": {"approved", "draft"},  # approved=advance, draft=reject-back
    "approved": {"signed"},
    "signed": {"delivered"},  # signed is immutable; only delivery can advance
    "delivered": set(),
}


def is_valid_transition(from_stage: str, to_stage: str) -> bool:
    return to_stage in _VALID_TRANSITIONS.get(from_stage, set())


def valid_next_stages(from_stage: str) -> list[str]:
    return sorted(_VALID_TRANSITIONS.get(from_stage, set()))


def can_sign(stage: str) -> bool:
    """Sign requires the report be in `approved` stage."""
    return stage == "approved"


def can_deliver(stage: str) -> bool:
    return stage == "signed"


def is_immutable_stage(stage: str) -> bool:
    return stage in {"signed", "delivered"}


__all__ = [
    "VALID_REPORT_TYPES",
    "VALID_STAGES",
    "is_valid_transition",
    "valid_next_stages",
    "can_sign",
    "can_deliver",
    "is_immutable_stage",
]
