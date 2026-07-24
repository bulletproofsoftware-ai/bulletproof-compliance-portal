"""WI-14 — Server-side YAML validation for SME-modified knowledge candidates.

Parses YAML safely (yaml.safe_load — never load_full or any unsafe loader),
checks structure against the schema for the candidate's knowledge_type, and
returns a structured ValidationResult with line numbers when available.

This is a structure check ONLY. Semantic validation is owned by the
compliance service (PRD 14). The portal must REFUSE to forward syntactically
or structurally invalid YAML so we never round-trip junk through the audit
chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass(slots=True)
class ValidationError:
    message: str
    line: int | None = None


@dataclass(slots=True)
class ValidationResult:
    ok: bool
    errors: list[ValidationError] = field(default_factory=list)
    parsed: Any | None = None


# Required top-level keys per knowledge_type. Mirrors PRD 14 schemas.
_REQUIRED_KEYS: dict[str, set[str]] = {
    "rule": {"id", "name", "description", "trigger", "action"},
    "decision_tree": {"id", "name", "root", "nodes"},
    "sop": {"id", "name", "steps"},
    "edge_case": {"id", "name", "trigger", "expected_behavior"},
}


def validate_candidate_yaml(
    yaml_text: str, knowledge_type: str
) -> ValidationResult:
    """Validate SME-edited YAML.

    Steps:
      1. yaml.safe_load — must succeed (yaml.YAMLError → error with line).
      2. Top-level must be a mapping (dict).
      3. Required keys per type must be present.
      4. id and name must be non-empty strings.

    Returns ValidationResult.ok=True only when ALL checks pass.
    """
    if not yaml_text or not yaml_text.strip():
        return ValidationResult(
            ok=False, errors=[ValidationError(message="empty_yaml")]
        )

    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        line: int | None = None
        if hasattr(exc, "problem_mark") and exc.problem_mark is not None:
            line = exc.problem_mark.line + 1  # type: ignore[attr-defined]
        return ValidationResult(
            ok=False,
            errors=[
                ValidationError(message=f"yaml_parse_error: {exc}", line=line)
            ],
        )

    if not isinstance(parsed, dict):
        return ValidationResult(
            ok=False,
            errors=[
                ValidationError(message="root_must_be_mapping")
            ],
            parsed=parsed,
        )

    errors: list[ValidationError] = []
    required = _REQUIRED_KEYS.get(knowledge_type)
    if required is None:
        errors.append(
            ValidationError(message=f"unknown_knowledge_type: {knowledge_type}")
        )
    else:
        missing = required - set(parsed.keys())
        for k in sorted(missing):
            errors.append(ValidationError(message=f"missing_required_key: {k}"))

    # id / name must be non-empty strings if present
    for k in ("id", "name"):
        v = parsed.get(k)
        if v is not None and not (isinstance(v, str) and v.strip()):
            errors.append(
                ValidationError(message=f"{k} must be a non-empty string")
            )

    return ValidationResult(ok=len(errors) == 0, errors=errors, parsed=parsed)


__all__ = ["ValidationError", "ValidationResult", "validate_candidate_yaml"]
