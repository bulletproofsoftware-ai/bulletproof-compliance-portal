"""WI-14 — YAML diff renderer for process knowledge candidates.

Generates line-level unified-diff between an existing YAML candidate (or empty
string when the candidate is wholly new) and the proposed YAML. Output is a
list of typed entries suitable for direct Jinja rendering — no template-side
diff math.

Uses Python's stdlib `difflib.unified_diff` so there are no extra deps and
the output format is well-known/stable.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class DiffLine:
    """Single line in a unified-diff for template rendering."""

    kind: Literal["context", "addition", "deletion", "header", "hunk"]
    text: str


def render_diff(
    existing: str | None, proposed: str, *, n: int = 3
) -> list[DiffLine]:
    """Produce a unified-diff line list.

    Empty / None `existing` is rendered as a wholly-new-file diff (every line
    of `proposed` becomes an addition).
    """
    existing_text = existing or ""
    a_lines = existing_text.splitlines(keepends=False)
    b_lines = (proposed or "").splitlines(keepends=False)

    raw_lines = list(
        difflib.unified_diff(
            a_lines,
            b_lines,
            fromfile="existing.yaml",
            tofile="proposed.yaml",
            lineterm="",
            n=n,
        )
    )

    result: list[DiffLine] = []
    for line in raw_lines:
        if line.startswith("---") or line.startswith("+++"):
            result.append(DiffLine(kind="header", text=line))
        elif line.startswith("@@"):
            result.append(DiffLine(kind="hunk", text=line))
        elif line.startswith("+"):
            result.append(DiffLine(kind="addition", text=line[1:]))
        elif line.startswith("-"):
            result.append(DiffLine(kind="deletion", text=line[1:]))
        else:
            # context (leading space) or stray
            result.append(
                DiffLine(
                    kind="context",
                    text=line[1:] if line.startswith(" ") else line,
                )
            )
    return result


def diff_summary(lines: list[DiffLine]) -> dict[str, int]:
    """Quick counts for header display."""
    additions = sum(1 for l in lines if l.kind == "addition")
    deletions = sum(1 for l in lines if l.kind == "deletion")
    return {"additions": additions, "deletions": deletions}


__all__ = ["DiffLine", "render_diff", "diff_summary"]
