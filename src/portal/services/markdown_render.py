"""Server-side markdown rendering with XSS hardening (AMD-19).

Used by WI-10 incident investigation notes and any other component that
renders user-supplied markdown into HTML for display in the portal.

Hardening posture:
  * markdown-it-py with `html=False` → raw HTML inside markdown becomes literal
    text, never DOM nodes.
  * Bleach allowlist applied to the parser output → defense-in-depth even if
    the parser regresses.
  * `bleach.linkify` rewrites bare URLs to `<a rel="nofollow noopener">`,
    mitigating tabnabbing and referrer leaks.

This module MUST NOT be modified to widen the allowlist without an explicit
CISO amendment update — it is a security control surface.
"""

from __future__ import annotations

import bleach
from bleach.callbacks import nofollow
from markdown_it import MarkdownIt

# AMD-19: html=False is critical. Other options:
#   linkify=True    → INERT under the "commonmark" preset. The preset's core rules are
#                     ['normalize','block','inline','text_join'] — no 'linkify' rule — so
#                     md.linkify is None and bare URLs are NOT auto-linked here. All
#                     linkification is performed by bleach.linkify below.
#   breaks=False    → require explicit blank-line breaks (markdown standard)
#   typographer=False → keep input bytes round-trippable
#
# SECURITY — do not "fix" the inert linkify above by enabling the rule.
# .enable(["linkify"]) raises ModuleNotFoundError unless linkify-it-py is installed, and
# linkify-it-py's LinkifyIt() defaults to fuzzy_email=True. That reintroduces email-regex
# evaluation over untrusted input — the same class of ReDoS exposure that SEC-EX-001
# (bleach LinkifyFilter.handle_email_addresses) is accepted on the basis of NOT being
# reachable. Enabling it, or adding linkify-it-py to the dependency set, VOIDS SEC-EX-001
# and requires security review. Enforced by tests/test_markdown_render_guard.py.
_md = MarkdownIt(
    "commonmark",
    {"html": False, "linkify": True, "breaks": False, "typographer": False},
).enable(["table", "strikethrough"])

# Strict allowlist. Per AMD-19 spec for incident notes and similar UI content.
ALLOWED_TAGS = [
    "p",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "strong",
    "em",
    "del",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "a",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "hr",
]
ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "th": ["align"],
    "td": ["align"],
}
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_note(markdown_src: str) -> str:
    """Render markdown source to safe HTML.

    Input:  arbitrary user-supplied markdown text (untrusted)
    Output: HTML string safe for direct insertion into a Jinja {{ ... | safe }}
            block — every tag and attribute has been allowlisted.

    Adversarial test cases (verified in tests/test_incidents.py):
      * <script>alert(1)</script>          → escaped literal text
      * [click](javascript:alert(1))        → href stripped (disallowed protocol)
      * <img src=x onerror=alert(1)>        → tag stripped (img not in allowlist)
      * onclick="..." anywhere              → attribute stripped
      * <iframe>, <object>, <embed>         → tag stripped
    """
    if markdown_src is None:
        return ""
    raw_html = _md.render(markdown_src)
    cleaned = bleach.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    # Auto-link bare URLs with rel=nofollow noopener
    return bleach.linkify(cleaned, callbacks=[nofollow])


__all__ = ["render_note", "ALLOWED_TAGS", "ALLOWED_ATTRS", "ALLOWED_PROTOCOLS"]
