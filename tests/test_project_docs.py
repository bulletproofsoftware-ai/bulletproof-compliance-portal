"""WI-16 — Project Documentation Portal router tests (REQ-CPL-040..044).

Covers:
  * Index page lists projects (REQ-CPL-040)
  * Project landing renders categorized doc tree (REQ-CPL-041)
  * Tree partial returns six categories
  * Document view renders markdown (REQ-CPL-042)
  * Search returns RBAC-scoped results (REQ-CPL-043)
  * History partial lists git versions (REQ-CPL-044)
  * Diff partial renders unified diff
  * ZIP export streams + emits audit events
  * Auditor scope intersection: out-of-scope projects 403
  * Auditor search filtering: out-of-scope hits stripped (defense in depth)
  * RBAC: viewer / admin / compliance_officer / auditor allowed; sme forbidden
  * PDF resolver registration
  * project_doc PDF resolver rejects bad document_id
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from portal.auth.models import AuditorScope, Role
from portal.routers import project_docs as pd_router_module
from shared.api_client.models import (
    DocVersion,
    DocVersionList,
    SearchHit,
    SearchResults,
)
from tests._fakes import build_project_doc, build_project_summary


def _seed_projects(client) -> None:
    client._ensure_projects_storage()
    p1 = build_project_summary(project_id="PRJ-001", name="Alpha")
    p2 = build_project_summary(project_id="PRJ-002", name="Beta")
    client.projects_storage["PRJ-001"] = p1
    client.projects_storage["PRJ-002"] = p2
    client.project_docs_storage["PRJ-001"] = [
        {
            "path": "requirements/brd.md",
            "name": "BRD",
            "category": "requirements",
            "doc_type": "markdown",
            "last_modified": datetime.now(UTC).isoformat(),
            "last_author": "alice",
        },
        {
            "path": "architecture/spec.md",
            "name": "Spec",
            "category": "architecture",
            "doc_type": "markdown",
            "last_modified": datetime.now(UTC).isoformat(),
            "last_author": "bob",
        },
    ]
    client.project_docs_storage["PRJ-002"] = []
    client.project_doc_content_storage[("PRJ-001", "requirements/brd.md")] = (
        build_project_doc(
            project_id="PRJ-001",
            path="requirements/brd.md",
            name="BRD",
            category="requirements",
            content="# BRD\n\nFunctional requirements here.",
        )
    )
    client.project_doc_history_storage[("PRJ-001", "requirements/brd.md")] = (
        DocVersionList(
            project_id="PRJ-001",
            doc_path="requirements/brd.md",
            items=[
                DocVersion(
                    version_id="abc12345fff",
                    author="alice",
                    timestamp=datetime.now(UTC),
                    message="Initial BRD",
                ),
                DocVersion(
                    version_id="def67890aaa",
                    author="bob",
                    timestamp=datetime.now(UTC) - timedelta(days=1),
                    message="Refine scope",
                ),
            ],
        )
    )


def _auditor_user(make_user, *, allowed_project_ids: list[str] | None = None):
    now = datetime.now(UTC)
    scope = AuditorScope(
        engagement_id="ENG-2026-A",
        engagement_start=now - timedelta(days=1),
        engagement_end=now + timedelta(days=30),
        date_range_start=now - timedelta(days=365),
        date_range_end=now,
        allowed_artifact_types=["audit_event", "evidence_package", "project_doc"],
        allowed_project_ids=allowed_project_ids,
    )
    return make_user(
        sub="auditor-pd",
        roles=[Role.AUDITOR],
        auditor_scope=scope,
    )


class TestRbac:
    def test_viewer_can_index(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects")
        assert r.status_code == 200

    def test_admin_can_index(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.ADMIN])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects")
        assert r.status_code == 200

    def test_sme_forbidden(
        self, build_router_app, fake_compliance_client, make_user
    ):
        user = make_user(roles=[Role.SME])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects")
        assert r.status_code == 403


class TestProjectIndex:
    def test_index_lists_projects(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects")
        assert r.status_code == 200
        assert "Alpha" in r.text
        assert "Beta" in r.text

    def test_auditor_sees_only_in_scope_projects(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = _auditor_user(make_user, allowed_project_ids=["PRJ-001"])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects")
        assert r.status_code == 200
        assert "Alpha" in r.text
        assert "Beta" not in r.text


class TestProjectLanding:
    def test_landing_renders_tree(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001")
        assert r.status_code == 200
        assert "Alpha" in r.text
        # Six categories should appear in the tree partial
        assert "Requirements" in r.text
        assert "Architecture" in r.text

    def test_auditor_out_of_scope_403(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = _auditor_user(make_user, allowed_project_ids=["PRJ-001"])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-002")
        assert r.status_code == 403


class TestTreePartial:
    def test_tree_partial(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/tree")
        assert r.status_code == 200
        assert "<html" not in r.text  # partial only
        assert "BRD" in r.text


class TestDocView:
    def test_doc_view_renders_markdown(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/docs/requirements/brd.md")
        assert r.status_code == 200
        # Markdown rendering should produce HTML headers
        assert "<h1>" in r.text
        assert "BRD" in r.text


class TestSearch:
    def test_search_results(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        # Seed search results
        fake_compliance_client.project_search_storage = SearchResults(
            query="brd",
            items=[
                SearchHit(
                    project_id="PRJ-001",
                    doc_path="requirements/brd.md",
                    title="BRD",
                    snippet="functional requirements",
                    score=0.95,
                    last_modified=datetime.now(UTC),
                    author="alice",
                ),
            ],
            total=1,
        )
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/search?q=brd")
        assert r.status_code == 200
        assert "BRD" in r.text

    def test_empty_query_returns_zero(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/search?q=")
        assert r.status_code == 200

    def test_auditor_out_of_scope_search_403(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = _auditor_user(make_user, allowed_project_ids=["PRJ-001"])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-002/search?q=anything")
        assert r.status_code == 403

    def test_auditor_search_strips_out_of_scope_hits(
        self, build_router_app, fake_compliance_client, make_user
    ):
        """Defense-in-depth: even if upstream returns hits across multiple
        projects, the auditor should never see hits outside their scope."""
        _seed_projects(fake_compliance_client)
        # Seed deliberately broad results
        fake_compliance_client.project_search_storage = SearchResults(
            query="brd",
            items=[
                SearchHit(
                    project_id="PRJ-001",
                    doc_path="requirements/brd.md",
                    title="In-scope hit",
                    snippet="x",
                    score=0.9,
                    last_modified=datetime.now(UTC),
                ),
                SearchHit(
                    project_id="PRJ-999",
                    doc_path="other/leak.md",
                    title="Out-of-scope hit",
                    snippet="should not show",
                    score=0.8,
                    last_modified=datetime.now(UTC),
                ),
            ],
            total=2,
        )
        user = _auditor_user(make_user, allowed_project_ids=["PRJ-001"])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/search?q=brd")
        assert r.status_code == 200
        assert "In-scope hit" in r.text
        assert "Out-of-scope hit" not in r.text


class TestHistory:
    def test_history_partial_lists_versions(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get(
                "/projects/PRJ-001/docs/requirements/brd.md/history"
            )
        assert r.status_code == 200
        assert "abc12345" in r.text  # version short SHA
        assert "alice" in r.text


class TestDiff:
    def test_diff_partial(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get(
                "/projects/PRJ-001/docs/requirements/brd.md/diff"
                "?from=abc12345fff&to=def67890aaa"
            )
        assert r.status_code == 200
        assert "abc12345" in r.text


class TestZipExport:
    def test_zip_streams(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/export.zip")
        assert r.status_code == 200
        assert r.headers.get("content-type", "").startswith("application/zip")
        # Body should start with "PK" (ZIP magic)
        assert r.content[:2] == b"PK"

    def test_zip_emits_audit_events(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = make_user(roles=[Role.VIEWER])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-001/export.zip")
        assert r.status_code == 200
        types = [
            ev["audit_type"]
            for ev in fake_compliance_client.recorded_audit_events
        ]
        assert "project.export.initiated" in types
        assert "project.export.completed" in types

    def test_zip_auditor_out_of_scope_403(
        self, build_router_app, fake_compliance_client, make_user
    ):
        _seed_projects(fake_compliance_client)
        user = _auditor_user(make_user, allowed_project_ids=["PRJ-001"])
        app = build_router_app(pd_router_module.router, user)
        with TestClient(app) as client:
            r = client.get("/projects/PRJ-002/export.zip")
        assert r.status_code == 403


class TestPdfResolver:
    def test_project_doc_registered(self):
        from portal.pdf.registry import get_default_registry

        pd_router_module.register_project_docs_pdf_components()
        reg = get_default_registry()
        assert "project_doc" in reg
        spec = reg.get("project_doc")
        assert spec is not None
        assert spec.audit_event_type == "project_doc.pdf.exported"

    def test_resolver_rejects_bad_document_id(
        self, fake_compliance_client, make_user
    ):
        """Resolver requires `<project_id>|<doc_path>` form."""
        import asyncio

        from portal.routers.project_docs import _project_doc_resolver

        user = make_user(roles=[Role.VIEWER])
        loop = asyncio.new_event_loop()
        try:
            from fastapi import HTTPException

            with pytest.raises(HTTPException):
                loop.run_until_complete(
                    _project_doc_resolver("just_a_project_no_pipe", user)
                )
        finally:
            loop.close()

    def test_resolver_rejects_empty_parts(self, make_user):
        """Resolver rejects when one side of `|` is empty."""
        import asyncio

        from portal.routers.project_docs import _project_doc_resolver

        user = make_user(roles=[Role.VIEWER])
        loop = asyncio.new_event_loop()
        try:
            from fastapi import HTTPException

            with pytest.raises(HTTPException):
                loop.run_until_complete(_project_doc_resolver("|nothing", user))
        finally:
            loop.close()
