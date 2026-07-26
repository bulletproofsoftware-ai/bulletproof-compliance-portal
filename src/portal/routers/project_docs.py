"""WI-16 — Project Documentation Portal (REQ-CPL-040..044).

Read-only browsable surface for documentation generated during conductor-
orchestrated project workflows. Per-project index, hierarchical document tree
organized by category (requirements, architecture, implementation, testing,
compliance, operations), server-side markdown rendering, OpenAPI/Swagger UI for
API specs, full-text search with RBAC scoping, git-backed version history with
diff view, and ZIP/PDF export.

Routes (mounted at /projects):

    GET  /projects                                                — index
    GET  /projects/{project_id}                                   — landing
    GET  /projects/{project_id}/tree                              — tree partial
    GET  /projects/{project_id}/docs/{doc_path:path}              — rendered doc
    GET  /projects/{project_id}/api-docs                          — Swagger UI
    GET  /projects/{project_id}/search?q=                         — search
    GET  /projects/{project_id}/docs/{doc_path:path}/history      — versions
    GET  /projects/{project_id}/docs/{doc_path:path}/diff         — diff view
    GET  /projects/{project_id}/export.zip                        — ZIP export

PDF resolver: project_doc — single document PDF via WI-19.

RBAC: viewer / admin / compliance_officer / auditor (auditor scope-clamped).
Auditor results are intersected with engagement allowed_project_ids; defense in
depth is performed by `services/project_docs.is_project_in_scope` even when the
service has already filtered upstream.
"""

from __future__ import annotations

# Aliased: this module uses `html` as a local variable for rendered document
# bodies, so the stdlib module name is not imported bare.
from html import escape as _escape
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from shared.api_client import ComplianceClient

from ..auth.models import Role, User
from ..auth.rbac import require_any_role
from ..config import get_settings
from ..dependencies import get_compliance_client
from ..logging import get_logger
from ..pdf import register_component
from ..services.project_docs import (
    DOC_CATEGORIES,
    build_doc_tree,
    filter_search_hits,
    intersect_auditor_scope,
    is_project_in_scope,
    render_doc_markdown,
    stream_project_zip,
)
from ..templates import get_templates

logger = get_logger(__name__)

router = APIRouter(prefix="/projects", tags=["projects"])

_ALLOWED = (
    Role.ADMIN,
    Role.COMPLIANCE_OFFICER,
    Role.AUDITOR,
    Role.VIEWER,
)


def _templates_dep() -> Jinja2Templates:
    return get_templates()


def _ensure_in_scope(user: User, project_id: str) -> None:
    """Reject auditors trying to access projects outside engagement scope."""
    if not is_project_in_scope(user, project_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="project not in auditor engagement scope",
        )


# ─────────────────────────────────────────────────────────────────────────────


@router.get("", response_class=HTMLResponse, name="projects_index")
async def projects_index(
    request: Request,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-040 — index of conductor-managed projects."""
    project_list = await client.list_projects()
    project_ids = [p.project_id for p in project_list.items]
    allowed_ids = set(intersect_auditor_scope(user, project_ids))
    visible = [p for p in project_list.items if p.project_id in allowed_ids]
    return templates.TemplateResponse(
        request,
        "project_docs/index.html",
        {
            "user": user,
            "projects": visible,
            "total": len(visible),
            "is_auditor_scoped": user.has_role(Role.AUDITOR)
            and len(visible) != len(project_list.items),
            "kpis": [
                {"label": "Projects", "value": len(visible)},
                {"label": "MAJOR tier", "value": sum(1 for p in visible if p.tier == "MAJOR")},
                {"label": "Documents", "value": sum((p.doc_count or 0) for p in visible)},
            ],
            "crumbs": [{"label": "Projects"}],
        },
    )


@router.get(
    "/{project_id}",
    response_class=HTMLResponse,
    name="projects_landing",
)
async def project_landing(
    request: Request,
    project_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-040/041 — per-project landing with document tree summary."""
    _ensure_in_scope(user, project_id)
    project = await client.get_project(project_id)
    raw_tree = await client.list_project_docs(project_id)
    nodes_raw = raw_tree.get("items", []) if isinstance(raw_tree, dict) else list(raw_tree)
    tree = build_doc_tree(nodes_raw)
    return templates.TemplateResponse(
        request,
        "project_docs/project_landing.html",
        {
            "user": user,
            "project": project,
            "tree": tree,
            "categories": DOC_CATEGORIES,
        },
    )


@router.get(
    "/{project_id}/tree",
    response_class=HTMLResponse,
    name="projects_tree_partial",
)
async def tree_partial(
    request: Request,
    project_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-041 — hierarchical document tree partial (HTMX)."""
    _ensure_in_scope(user, project_id)
    raw_tree = await client.list_project_docs(project_id)
    nodes_raw = raw_tree.get("items", []) if isinstance(raw_tree, dict) else list(raw_tree)
    tree = build_doc_tree(nodes_raw)
    return templates.TemplateResponse(
        request,
        "project_docs/tree_partial.html",
        {
            "user": user,
            "project_id": project_id,
            "tree": tree,
            "categories": DOC_CATEGORIES,
        },
    )


@router.get(
    "/{project_id}/api-docs",
    response_class=HTMLResponse,
    name="projects_api_docs",
)
async def api_docs(
    request: Request,
    project_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-042 — Swagger UI host page for project OpenAPI specs."""
    _ensure_in_scope(user, project_id)
    project = await client.get_project(project_id)
    return templates.TemplateResponse(
        request,
        "project_docs/api_docs.html",
        {
            "user": user,
            "project": project,
            "openapi_url": f"/projects/{project_id}/docs/openapi.json",
        },
    )


@router.get(
    "/{project_id}/search",
    response_class=HTMLResponse,
    name="projects_search",
)
async def projects_search(
    request: Request,
    project_id: str,
    q: str = Query(default=""),
    doc_type: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    author: str | None = None,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-043 — full-text search with RBAC scoping."""
    _ensure_in_scope(user, project_id)
    if not q.strip():
        return templates.TemplateResponse(
            request,
            "project_docs/search_partial.html",
            {
                "user": user,
                "project_id": project_id,
                "query": q,
                "results": [],
                "total": 0,
            },
        )

    project_ids = [project_id]
    allowed = intersect_auditor_scope(user, project_ids)
    if not allowed:
        # Auditor with no scope hit on this project — return empty.
        return templates.TemplateResponse(
            request,
            "project_docs/search_partial.html",
            {
                "user": user,
                "project_id": project_id,
                "query": q,
                "results": [],
                "total": 0,
            },
        )

    results = await client.search_project_docs(
        q=q,
        project_ids=allowed,
        doc_types=[doc_type] if doc_type else None,
        date_from=date_from,
        date_to=date_to,
        author=author,
    )
    # Defense in depth: filter again on portal side.
    safe_hits = filter_search_hits(user, list(results.items))
    return templates.TemplateResponse(
        request,
        "project_docs/search_partial.html",
        {
            "user": user,
            "project_id": project_id,
            "query": q,
            "results": safe_hits,
            "total": len(safe_hits),
        },
    )


@router.get(
    "/{project_id}/export.zip",
    name="projects_export_zip",
)
async def export_zip(
    project_id: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
) -> StreamingResponse:
    """REQ-CPL-044 — bundled ZIP export of project documentation."""
    _ensure_in_scope(user, project_id)

    # REQ-CPL-045 audit: emit init + completion events.
    try:
        await client.record_audit_event(
            audit_type="project.export.initiated",
            user_id=user.sub,
            classification="internal",
            payload={"project_id": project_id, "format": "zip"},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "projects.export.audit_init_failed",
            project_id=project_id,
            error=str(exc),
        )

    async def _gen():
        async for chunk in stream_project_zip(project_id, user, client):
            yield chunk
        try:
            await client.record_audit_event(
                audit_type="project.export.completed",
                user_id=user.sub,
                classification="internal",
                payload={"project_id": project_id, "format": "zip"},
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "projects.export.audit_complete_failed",
                project_id=project_id,
                error=str(exc),
            )

    headers = {
        "Content-Disposition": f'attachment; filename="{project_id}.zip"',
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(
        _gen(),
        media_type="application/zip",
        headers=headers,
    )


# Note: history/diff/doc-view routes use `:path` so doc_path can contain `/`.
# These MUST be registered AFTER all other `/projects/{project_id}/...`
# routes that share the prefix, otherwise FastAPI's matcher would consume
# `/{project_id}/tree` as `doc_path=tree`. Order matters here.


@router.get(
    "/{project_id}/docs/{doc_path:path}/history",
    response_class=HTMLResponse,
    name="projects_doc_history",
)
async def doc_history(
    request: Request,
    project_id: str,
    doc_path: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-044 — git-backed version history."""
    _ensure_in_scope(user, project_id)
    history = await client.get_project_doc_history(project_id, doc_path)
    return templates.TemplateResponse(
        request,
        "project_docs/history_partial.html",
        {
            "user": user,
            "project_id": project_id,
            "doc_path": doc_path,
            "history": history,
        },
    )


@router.get(
    "/{project_id}/docs/{doc_path:path}/diff",
    response_class=HTMLResponse,
    name="projects_doc_diff",
)
async def doc_diff(
    request: Request,
    project_id: str,
    doc_path: str,
    from_: str = Query(..., alias="from"),
    to: str = Query(...),
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-044 — diff view between two SHAs."""
    _ensure_in_scope(user, project_id)
    diff = await client.get_doc_diff(project_id, doc_path, from_, to)
    return templates.TemplateResponse(
        request,
        "project_docs/diff_partial.html",
        {
            "user": user,
            "project_id": project_id,
            "doc_path": doc_path,
            "diff": diff,
            "from_sha": from_,
            "to_sha": to,
        },
    )


@router.get(
    "/{project_id}/docs/{doc_path:path}",
    response_class=HTMLResponse,
    name="projects_doc_view",
)
async def doc_view(
    request: Request,
    project_id: str,
    doc_path: str,
    user: User = Depends(require_any_role(*_ALLOWED)),
    client: ComplianceClient = Depends(get_compliance_client),
    templates: Jinja2Templates = Depends(_templates_dep),
) -> HTMLResponse:
    """REQ-CPL-042 — rendered markdown document via project_docs service."""
    _ensure_in_scope(user, project_id)
    # If a relative link inside a doc bubbled the doc_path up a level (e.g.
    # the doc at TODO/foo.md linked to TODO/bar.md, which the browser
    # resolved against the doc's directory → TODO/TODO/bar.md), normalise the
    # path by collapsing duplicated leading directory segments before failing.
    from shared.api_client.exceptions import NotFoundError as _NotFound
    try:
        doc = await client.get_project_doc(project_id, doc_path)
    except _NotFound:
        normalised = _normalise_doc_path(doc_path)
        if normalised and normalised != doc_path:
            try:
                doc = await client.get_project_doc(project_id, normalised)
            except _NotFound:
                return _render_missing_doc_page(request, user, project_id, doc_path, templates)
        else:
            return _render_missing_doc_page(request, user, project_id, doc_path, templates)
    # Prefer service-side rendered HTML if present; otherwise render locally
    # with the AMD-19-hardened markdown pipeline.
    html = doc.rendered_html or render_doc_markdown(doc.content or "")
    # Rewrite relative <a href="*.md"> links inside the doc body to absolute
    # /projects/{id}/docs/... URLs so the browser doesn't resolve them against
    # the current page's directory (which would double-prefix subdirs).
    html = _rewrite_doc_links(html, project_id, doc_path)
    return templates.TemplateResponse(
        request,
        "project_docs/doc_view.html",
        {
            "user": user,
            "project_id": project_id,
            "doc": doc,
            "doc_html": html,
        },
    )


def _normalise_doc_path(p: str) -> str | None:
    """Collapse duplicated leading directory segments — TODO/TODO/x.md → TODO/x.md."""
    parts = [seg for seg in p.split("/") if seg]
    if len(parts) >= 2 and parts[0] == parts[1]:
        return "/".join(parts[1:])
    return None


def _render_missing_doc_page(
    request: Request,
    user: User,
    project_id: str,
    doc_path: str,
    templates: Jinja2Templates,
) -> HTMLResponse:
    """Render a friendly 200 page for dangling markdown link refs.

    The vast majority of "not found" doc paths in real conductor projects are
    cross-references inside markdown bodies pointing at files that don't
    physically exist in the project tree (auto-generated stubs, planned-but-
    never-created docs, copy/paste from sibling projects). Returning a hard
    404 breaks link-checkers and gives a hostile UX. Instead, render a 200
    page with a clear message + a link back to the project doc index.
    """
    # Escape with the stdlib, not by hand. The previous version replaced only
    # "<" and ">", which leaves the double quote intact -- and safe_project_id
    # is interpolated inside an href="..." attribute below. A project_id of
    #     x" onmouseover="alert(1)
    # therefore closed the attribute and added a live event handler without
    # using a single angle bracket. user_chip was not escaped at all.
    # _escape covers & < > " ' (quote=True by default).
    safe_doc_path = _escape(doc_path)
    safe_project_id = _escape(project_id)
    user_chip = _escape(
        f"{user.email or user.sub} ({user.roles[0].value if user.roles else 'viewer'})"
        if user else "—"
    )
    body = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Doc not found — {safe_project_id}</title>
  <style>
    :root {{ --muted:#6b7280; --line:#e5e7eb; --accent:#1f2937; --amber:#b45309; }}
    body {{ margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
            color:#111827; background:#f6f7f9; }}
    nav.topbar {{ display:flex; align-items:center; gap:1.5rem; padding:.75rem 1.25rem;
                  background:var(--accent); color:#fff; border-bottom:1px solid var(--line); }}
    nav.topbar a {{ color:#fff; text-decoration:none; }}
    nav.topbar .brand {{ font-weight:700; }}
    nav.topbar .spacer {{ flex:1; }}
    main.content {{ padding:1.5rem 1.25rem; max-width:900px; margin:0 auto; }}
    .alert-warn {{ border-left:4px solid var(--amber); background:#fffbeb; color:var(--amber);
                   padding:.75rem 1rem; margin:1rem 0; }}
    .panel {{ background:#fff; border:1px solid var(--line); border-radius:6px; padding:1rem;
              margin-bottom:1rem; }}
    .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }}
    a {{ color:#1d4ed8; text-decoration:none; }}
    a:hover {{ text-decoration:underline; }}
  </style>
</head>
<body>
  <nav class="topbar">
    <span class="brand">Compliance Portal</span>
    <a href="/audit">Audit</a>
    <a href="/evidence">Evidence</a>
    <a href="/gates">Gates</a>
    <a href="/dashboards">Dashboards</a>
    <a href="/knowledge">Knowledge</a>
    <a href="/outcomes">Outcomes</a>
    <a href="/projects">Projects</a>
    <span class="spacer"></span>
    <span class="muted">{user_chip}</span>
    <a href="/auth/logout">Log out</a>
  </nav>
  <main class="content">
    <h1>Doc not found</h1>
    <p class="muted">The doc referenced by this link doesn't exist in the project tree.</p>
    <div class="alert-warn">
      <strong>Path:</strong> <span class="mono">{safe_doc_path}</span><br>
      <strong>Project:</strong> <span class="mono">{safe_project_id}</span>
    </div>
    <div class="panel">
      <p>This usually means the markdown link points to a file that was renamed,
         removed, or never created. If this is your project, search for the
         basename below in the project tree or update the link in the referring
         document.</p>
      <p>
        <a href="/projects/{safe_project_id}">← Back to {safe_project_id} index</a> &middot;
        <a href="/projects">All projects</a>
      </p>
    </div>
  </main>
</body>
</html>"""
    return HTMLResponse(content=body, status_code=200)


def _rewrite_doc_links(html: str, project_id: str, current_doc_path: str) -> str:
    """Rewrite relative markdown links to absolute /projects/{id}/docs/... URLs.

    A markdown link [foo](TODO/bar.md) renders as <a href="TODO/bar.md">. The
    browser resolves that against the current URL's directory which silently
    breaks for any doc not at the project root. Walk every <a> and absolute-
    ify any href that doesn't start with '/', 'http', '#', or 'mailto:'.
    """
    import re as _re

    def _abs(match: "_re.Match[str]") -> str:
        attrs = match.group(1)
        href_m = _re.search(r"href=\"([^\"]+)\"", attrs)
        if not href_m:
            return match.group(0)
        original_href = href_m.group(1)
        href = original_href
        if href.startswith(("/", "#", "mailto:", "tel:")):
            return match.group(0)
        # markdown-it autolinks bare *.md tokens as http://x.md or
        # http://path/x.md — those are NEVER real external URLs. Strip the
        # scheme and treat as a relative doc reference. Real external links
        # (with a real-looking TLD in the host) keep their scheme.
        if href.startswith(("http://", "https://")):
            _scheme, _, rest = href.partition("://")
            host = rest.split("/", 1)[0]
            looks_like_real_domain = "." in host and host.split(".")[-1].isalpha() and len(host.split(".")[-1]) >= 2 and host.split(".")[-1] not in ("md",)
            if rest.endswith(".md") and not looks_like_real_domain:
                href = rest  # treat as relative path
            else:
                return match.group(0)
        # Anchor-only (fragment) preserved
        if href.startswith("?"):
            return match.group(0)
        # Resolve relative to the current doc's directory
        cur_dir = "/".join(current_doc_path.split("/")[:-1])
        if cur_dir:
            target = f"{cur_dir}/{href}"
        else:
            target = href
        # Collapse any ./ or // segments
        parts: list[str] = []
        for seg in target.split("/"):
            if seg in ("", ".."):
                if seg == ".." and parts:
                    parts.pop()
                continue
            if seg == ".":
                continue
            parts.append(seg)
        target = "/".join(parts)
        new_href = f"/projects/{project_id}/docs/{target}"
        new_attrs = attrs.replace(f'href="{original_href}"', f'href="{new_href}"')
        return f"<a{new_attrs}>"

    return _re.sub(r"<a([^>]*)>", _abs, html)


# ─────────────────────────────────────────────────────────────────────────────
# PDF resolver — project_doc
# ─────────────────────────────────────────────────────────────────────────────


async def _project_doc_resolver(
    document_id: str, user: User
) -> tuple[str, dict[str, Any], str, str]:
    """Resolver for /export/pdf/project_doc/{project_id}|{doc_path}.

    `document_id` is encoded as `<project_id>|<doc_path>`. Auditor scope is
    enforced — if the project is out of scope the resolver raises 403.
    """
    from shared.api_client import ComplianceClient as _Client

    if "|" not in document_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="document_id must be '<project_id>|<doc_path>'",
        )
    project_id, doc_path = document_id.split("|", 1)
    if not project_id or not doc_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="project_id and doc_path are required",
        )
    if not is_project_in_scope(user, project_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="project not in auditor engagement scope",
        )

    settings = get_settings()
    async with _Client(
        base_url=str(settings.compliance_api_base_url),
        token=settings.compliance_api_token.get_secret_value(),
        timeout_s=settings.compliance_api_timeout_s,
        user_sub=user.sub,
        request_id=None,
        auditor_scope=user.auditor_scope.model_dump(mode="json")
        if user.auditor_scope
        else None,
    ) as c:
        doc = await c.get_project_doc(project_id, doc_path)
        history = await c.get_project_doc_history(project_id, doc_path)
        project = await c.get_project(project_id)

    html = doc.rendered_html or render_doc_markdown(doc.content or "")
    doc_dict = doc.model_dump(mode="json")
    # The PDF template (portal/pdf/templates/project_doc.html) reads body_html,
    # body_text, title, author, last_modified_at, id, version — different names
    # than the portal's HTML view. Map them so the body actually renders.
    doc_dict["body_html"] = html
    doc_dict["body_text"] = doc.content or ""
    doc_dict["title"] = doc.name
    doc_dict["author"] = doc.last_author or "—"
    doc_dict["last_modified_at"] = doc.last_modified.isoformat() if doc.last_modified else "—"
    doc_dict["id"] = doc.path
    doc_dict.setdefault("version", "v1")
    ctx = {
        "project": project.model_dump(mode="json"),
        "doc": doc_dict,
        "doc_html": html,
        "history": history.model_dump(mode="json"),
    }
    return (
        "project_doc.html",
        ctx,
        f"{project.name} — {doc.name}",
        "internal",
    )


def register_project_docs_pdf_components() -> None:
    from ..pdf.registry import get_default_registry

    reg = get_default_registry()
    if "project_doc" not in reg:
        register_component(
            "project_doc",
            template="project_doc.html",
            resolver=_project_doc_resolver,
            audit_event_type="project_doc.pdf.exported",
            allowed_roles={"admin", "compliance_officer", "auditor", "viewer"},
        )


register_project_docs_pdf_components()


__all__ = [
    "router",
    "register_project_docs_pdf_components",
]
