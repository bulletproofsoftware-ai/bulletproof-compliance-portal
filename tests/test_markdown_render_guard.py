"""Enforceable guards for SEC-EX-001 (bleach ReDoS accepted as unreachable).

SEC-EX-001 accepts a ReDoS in bleach's LinkifyFilter.handle_email_addresses()
on the sole basis that the vulnerable code path is NEVER REACHED: it requires
parse_email=True, and this codebase never passes it.

That acceptance is only valid while the preconditions hold. A prose note in
docs/SECURITY-EXCEPTIONS.md cannot enforce them; these tests can. If any of
these fail, SEC-EX-001 is VOID and the finding becomes live — do not "fix" the
test, escalate for security review.

CISO condition C1, 2026-07-27.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import bleach
import pytest
from bleach.linkifier import LinkifyFilter

SRC = Path(__file__).resolve().parent.parent / "src"


def _python_sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def test_src_tree_is_non_empty() -> None:
    """Guard the guard: if the glob breaks, the scans below silently pass."""
    files = _python_sources()
    assert len(files) > 20, f"expected a populated src/ tree, found {len(files)} files"


def test_parse_email_never_appears_in_source() -> None:
    """parse_email=True reaches bleach's vulnerable email regex. It must not appear.

    This is the precondition SEC-EX-001 rests on.
    """
    offenders = [
        f"{p.relative_to(SRC.parent)}:{i}: {line.strip()}"
        for p in _python_sources()
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if "parse_email" in line
    ]
    assert not offenders, (
        "parse_email found in source — this VOIDS SEC-EX-001 and makes the bleach "
        "ReDoS (SNYK-PYTHON-BLEACH-17356127) live:\n  " + "\n  ".join(offenders)
    )


def test_bleach_linkify_default_is_still_parse_email_false() -> None:
    """If bleach ever flips the default, omitting the argument stops being safe."""
    assert inspect.signature(bleach.linkify).parameters["parse_email"].default is False
    assert (
        inspect.signature(LinkifyFilter.__init__).parameters["parse_email"].default
        is False
    )


def test_markdown_it_linkify_is_inert() -> None:
    """The renderer's linkify:True is inert under the commonmark preset.

    Enabling it requires linkify-it-py, whose LinkifyIt() defaults to
    fuzzy_email=True — reintroducing email-regex evaluation over untrusted input.
    """
    from portal.services.markdown_render import _md

    assert _md.linkify is None, (
        "markdown-it linkify is active — linkify-it-py is installed and the rule "
        "enabled. Its fuzzy_email=True default reintroduces email-regex evaluation "
        "over untrusted input. This VOIDS SEC-EX-001."
    )


def test_linkify_it_py_not_in_dependency_set() -> None:
    """linkify-it-py entering the tree is the supply-chain route to the same risk."""
    root = SRC.parent
    for manifest in ("requirements.txt", "pyproject.toml"):
        p = root / manifest
        if p.exists():
            assert "linkify-it-py" not in p.read_text(encoding="utf-8"), (
                f"linkify-it-py added to {manifest}. Its fuzzy_email=True default "
                "reintroduces the accepted-as-unreachable ReDoS. VOIDS SEC-EX-001."
            )


@pytest.mark.parametrize(
    "payload",
    [
        "Visit https://example.com and mail bob@example.com",
        "a" * 500 + "@" + "b" * 100,
        "!#$%&'*+-/=?^_`{|}~" * 40 + "@example.com",
    ],
)
def test_render_note_does_not_evaluate_email_regex(payload: str) -> None:
    """Rendering must stay fast and must not linkify emails.

    A bare mailto: in the output would mean the email path ran.
    """
    from portal.services.markdown_render import render_note

    out = render_note(payload)
    assert "mailto:" not in out, "email linkification occurred — the ReDoS path is live"


def test_render_note_still_blocks_xss() -> None:
    """Regression cover for the control this module actually exists to provide.

    Assert the security PROPERTY (no executable sink), not the absence of a
    substring. Dangerous schemes are rejected by markdown-it's link validator, so
    `[click](javascript:alert(1))` renders as inert literal text — the string
    "javascript:" is still present but is not an href and cannot execute.
    """
    from portal.services.markdown_render import render_note

    # Dangerous URL schemes must never become an anchor href.
    for src in (
        "[click](javascript:alert(1))",
        "[x](data:text/html;base64,PHNjcmlwdD4=)",
        "[y](vbscript:msgbox(1))",
    ):
        out = render_note(src).lower()
        assert "<a " not in out, f"dangerous scheme became a link: {out!r}"
        assert 'href="javascript:' not in out
        assert 'href="data:' not in out

    # Raw HTML must be escaped into text, never emitted as tags.
    assert "<script" not in render_note("<script>alert(1)</script>").lower()
    assert "<img" not in render_note("<img src=x onerror=alert(1)>").lower()
    assert "<iframe" not in render_note("<iframe src=evil></iframe>").lower()

    # Legitimate links still work and carry the anti-tabnabbing rel.
    ok = render_note("[ok](https://example.com)")
    assert '<a href="https://example.com"' in ok and 'rel="nofollow"' in ok
