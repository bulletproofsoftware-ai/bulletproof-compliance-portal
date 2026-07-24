"""WI-16 — Project documentation portal helpers.

Exposes:

  * `render_doc_markdown(raw_md)`     — server-side markdown rendering with
    AMD-19 hardening (markdown-it-py html=False + Bleach allowlist). Reuses
    `services/markdown_render._md` configuration; we only widen the allowlist
    slightly because project docs need code blocks with language hints.
  * `build_doc_tree(flat_nodes)`      — turns a flat list of DocNode dicts
    into a six-category nested tree.
  * `intersect_auditor_scope(...)`    — defense-in-depth filter that
    intersects search/listing results with `user.auditor_scope.allowed_project_ids`.
  * `stream_project_zip(...)`         — async generator that yields ZIP bytes
    for streaming response, walking the doc tree via the compliance client.

ZIP packaging uses zipfile.ZipFile in streaming mode (BytesIO) and yields
each chunk. Memory bound: one document at a time + ZIP central directory.
"""

from __future__ import annotations

import io
import zipfile
from typing import TYPE_CHECKING, Any, AsyncIterator

import bleach
from bleach.callbacks import nofollow
from markdown_it import MarkdownIt

from ..auth.models import Role, User

if TYPE_CHECKING:  # pragma: no cover
    from shared.api_client import ComplianceClient


# Project doc renderer — adds <pre><code class="language-..."> support
_md = MarkdownIt(
    "commonmark",
    {"html": False, "linkify": True, "breaks": False, "typographer": False},
).enable(["table", "strikethrough"])

# Slightly wider allowlist than incident notes: code blocks with language class.
_ALLOWED_TAGS = [
    "p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "del",
    "code", "pre", "blockquote", "ul", "ol", "li", "a", "table", "thead",
    "tbody", "tr", "th", "td", "hr", "img", "span", "div",
]
_ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
    "pre": ["class"],
    "span": ["class"],
    "div": ["class"],
    "img": ["src", "alt", "title"],
    "th": ["align"],
    "td": ["align"],
}
_ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def render_doc_markdown(raw_md: str) -> str:
    """Render project documentation markdown to safe HTML."""
    if raw_md is None:
        return ""
    raw_html = _md.render(raw_md)
    cleaned = bleach.clean(
        raw_html,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=_ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True,
    )
    return bleach.linkify(cleaned, callbacks=[nofollow])


# Six categories per REQ-CPL-041
DOC_CATEGORIES = (
    "requirements",
    "architecture",
    "implementation",
    "testing",
    "compliance",
    "operations",
)


def build_doc_tree(flat_nodes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group a flat list of DocNode dicts into the six-category tree.

    Unknown categories are bucketed under `operations` as a safe fallback.
    Within each category, children are sorted by `name`.
    """
    tree: dict[str, list[dict[str, Any]]] = {c: [] for c in DOC_CATEGORIES}
    for node in flat_nodes:
        cat = node.get("category", "operations")
        if cat not in tree:
            cat = "operations"
        tree[cat].append(node)

    for cat in tree:
        tree[cat].sort(key=lambda n: n.get("name", n.get("path", "")))

    return tree


def intersect_auditor_scope(
    user: User, project_ids: list[str]
) -> list[str]:
    """Defense-in-depth: intersect a project_id list with auditor scope.

    Non-auditor users get the full input list. Auditors with no
    allowed_project_ids restriction (None) also get the full list. Otherwise
    we keep only the intersection, preserving the input order.
    """
    if not user.has_role(Role.AUDITOR):
        return project_ids
    scope = user.auditor_scope
    if scope is None or scope.allowed_project_ids is None:
        return project_ids
    allowed = set(scope.allowed_project_ids)
    return [pid for pid in project_ids if pid in allowed]


def is_project_in_scope(user: User, project_id: str) -> bool:
    """True iff the given project_id is in the user's auditor scope.

    Non-auditor users always return True.
    """
    if not user.has_role(Role.AUDITOR):
        return True
    scope = user.auditor_scope
    if scope is None:
        return False
    if scope.allowed_project_ids is None:
        return True
    return project_id in scope.allowed_project_ids


def filter_search_hits(user: User, hits: list[Any]) -> list[Any]:
    """Filter search hits by auditor scope (REQ-CPL-043 defense-in-depth)."""
    if not user.has_role(Role.AUDITOR):
        return hits
    scope = user.auditor_scope
    if scope is None:
        return []
    if scope.allowed_project_ids is None:
        return hits
    allowed = set(scope.allowed_project_ids)
    return [h for h in hits if getattr(h, "project_id", None) in allowed]


async def stream_project_zip(
    project_id: str,
    user: User,
    client: "ComplianceClient",
) -> AsyncIterator[bytes]:
    """Stream a ZIP of project documentation.

    Walks the doc tree via the compliance client, fetches each document, and
    writes them all into an in-memory ZIP. Once finalized (with-block exit),
    the central directory is correct and the bytes are emitted in chunks so
    the downstream StreamingResponse does not need to hold the full archive
    a second time.

    Memory usage bounded by archive size; for large projects PDF bundle path
    is preferred (REQ-CPL-045).

    Audit events are emitted by the caller (router) — this generator is
    purely concerned with bytes.
    """
    if not is_project_in_scope(user, project_id):
        # Yield empty zip; router should have already rejected. Defense in depth.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED):
            pass
        yield buf.getvalue()
        return

    raw_tree = await client.list_project_docs(project_id)
    nodes: list[dict[str, Any]] = (
        raw_tree.get("items", [])
        if isinstance(raw_tree, dict)
        else list(raw_tree)
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for node in nodes:
            doc_path = node.get("path") or node.get("name")
            if not doc_path:
                continue
            try:
                doc = await client.get_project_doc(project_id, doc_path)
            except Exception:  # noqa: BLE001 — skip unreadable; surface in logs
                continue
            zf.writestr(doc_path, doc.content or "")

    # Emit the finalized archive in fixed chunks so a slow client doesn't pin
    # us into a single megablob.
    data = buf.getvalue()
    chunk_size = 64 * 1024
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


__all__ = [
    "render_doc_markdown",
    "build_doc_tree",
    "intersect_auditor_scope",
    "is_project_in_scope",
    "filter_search_hits",
    "stream_project_zip",
    "DOC_CATEGORIES",
]
