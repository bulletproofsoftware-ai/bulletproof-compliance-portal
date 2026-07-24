"""Public-portal identity verification policy state machine (AMD-01).

GDPR Article 12(6) requires the controller to verify identity before honouring
any DSR action that exposes or alters subject data. CAPTCHA + reference is
NOT identity verification — it is anti-bot + lookup. The reviewer (compliance
officer in the internal portal) MUST personally verify identity proof before
the request advances to `verified`.

Sub-state machine inserted between `received` and `processing`:

    received → identity_pending → verified → processing
                       │              ↑
                       ├─ identity_insufficient ┘  (re-upload via SAME ref)
                       │
                       └─ identity_rejected (terminal — fraud/abuse)

SoD rule (AMD-01): the reviewer MUST NOT be the same identity that submitted
the DSR. The compliance service enforces authoritatively; this module exposes
the helpers used by the public app and the WI-08 internal router.

Always-officer-review request types (REQ-CPL-012):
    - erasure                    (Art 17 — irreversible)
    - automated_decision_review  (Art 22 — adverse-action exposure)
    - rectification              (Art 16 — modifies stored data)
"""

from __future__ import annotations

from enum import StrEnum


class IdentityState(StrEnum):
    RECEIVED = "received"
    IDENTITY_PENDING = "identity_pending"
    IDENTITY_INSUFFICIENT = "identity_insufficient"
    IDENTITY_REJECTED = "identity_rejected"
    VERIFIED = "verified"


# Allowed forward transitions in the identity sub-state machine.
ALLOWED_TRANSITIONS: dict[IdentityState, set[IdentityState]] = {
    IdentityState.RECEIVED: {IdentityState.IDENTITY_PENDING},
    IdentityState.IDENTITY_PENDING: {
        IdentityState.VERIFIED,
        IdentityState.IDENTITY_INSUFFICIENT,
        IdentityState.IDENTITY_REJECTED,
    },
    IdentityState.IDENTITY_INSUFFICIENT: {
        IdentityState.IDENTITY_PENDING,  # re-upload attempt
        IdentityState.IDENTITY_REJECTED,
    },
    IdentityState.IDENTITY_REJECTED: set(),  # terminal
    IdentityState.VERIFIED: set(),  # exits the sub-state machine
}

# Request types where the reviewer MUST personally inspect identity proof.
# Phase 2 scope: ALL types (always-manual). The list is documented for
# Phase 4 risk-tiered automation.
ALWAYS_OFFICER_REVIEW_TYPES = frozenset(
    {"erasure", "automated_decision_review", "rectification"}
)


def is_valid_transition(
    from_state: IdentityState, to_state: IdentityState
) -> bool:
    return to_state in ALLOWED_TRANSITIONS.get(from_state, set())


def is_terminal(state: IdentityState) -> bool:
    return state == IdentityState.IDENTITY_REJECTED


def requires_officer_review(request_type: str) -> bool:
    """Phase 2: returns True for all types (always-manual review)."""
    # Even outside ALWAYS list, Phase 2 scope is always-manual.
    return True


def sod_violation(submitter_sub: str | None, reviewer_sub: str) -> bool:
    """AMD-01 SoD pre-check. Returns True iff the reviewer cannot decide."""
    if not submitter_sub or not reviewer_sub:
        return False
    return submitter_sub == reviewer_sub


__all__ = [
    "IdentityState",
    "ALLOWED_TRANSITIONS",
    "ALWAYS_OFFICER_REVIEW_TYPES",
    "is_valid_transition",
    "is_terminal",
    "requires_officer_review",
    "sod_violation",
]
