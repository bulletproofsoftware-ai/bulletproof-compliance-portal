"""WI-18 — validate the Docker Compose deployment manifest.

These tests assert structural invariants that REQ-CPL-001, REQ-CPL-003 and
REQ-CPL-036 depend on. They run in the standard pytest suite and do NOT
require a live Docker daemon.

Coverage:
    * compose.yaml parses as valid YAML
    * Required services present (portal, dsr_portal, portal_nginx, public_nginx, redis)
    * Each service has a healthcheck
    * Network isolation: portal-net and public-net never share a service
    * dsr_portal lives only on public-net (cannot reach redis/postgres)
    * Both Dockerfiles use a non-root UID (10001)
    * entrypoint.sh enforces the AMD-20 group_role_mapping allowlist
    * nginx public.conf enforces AMD-11 body limits + AMD-21 TLS pinning
    * nginx internal.conf enforces AMD-21 TLS pinning
    * .dockerignore excludes secrets / tests / state files
    * secrets.example/ is populated with placeholder files
    * SBOM.md and README.md exist
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = REPO_ROOT / "docker"
COMPOSE_PATH = DOCKER_DIR / "compose.yaml"
DOCKERFILE_PORTAL = DOCKER_DIR / "Dockerfile.portal"
DOCKERFILE_DSR = DOCKER_DIR / "Dockerfile.dsr_portal"
ENTRYPOINT = DOCKER_DIR / "entrypoint.sh"
NGINX_INTERNAL = DOCKER_DIR / "nginx" / "internal.conf"
NGINX_PUBLIC = DOCKER_DIR / "nginx" / "public.conf"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
SBOM_DOC = DOCKER_DIR / "SBOM.md"
DOCKER_README = DOCKER_DIR / "README.md"
SECRETS_EXAMPLE = DOCKER_DIR / "secrets.example"


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def compose() -> dict:
    """Parse compose.yaml once per module."""
    assert COMPOSE_PATH.is_file(), f"compose.yaml missing at {COMPOSE_PATH}"
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


# ─── Compose structure ───────────────────────────────────────────────────────


def test_compose_yaml_parses(compose: dict) -> None:
    """compose.yaml must be syntactically valid YAML and have a services map."""
    assert isinstance(compose, dict)
    assert "services" in compose
    assert isinstance(compose["services"], dict)


def test_compose_required_services_present(compose: dict) -> None:
    """All deliverable services exist in compose.yaml."""
    required = {"portal", "dsr_portal", "portal_nginx", "public_nginx", "redis"}
    have = set(compose["services"].keys())
    missing = required - have
    assert not missing, f"missing services: {missing}"


def test_compose_every_service_has_healthcheck(compose: dict) -> None:
    """REQ-CPL-001: every long-running service must declare a healthcheck."""
    for name, svc in compose["services"].items():
        # postgres is profile-gated for dev — still has its own healthcheck
        assert "healthcheck" in svc, f"service {name!r} missing healthcheck"
        hc = svc["healthcheck"]
        assert "test" in hc, f"service {name!r} healthcheck missing test"


def test_compose_required_networks_present(compose: dict) -> None:
    """The three required networks must be declared."""
    assert "networks" in compose
    nets = set(compose["networks"].keys())
    required = {"portal-net", "public-net", "internal-mgmt"}
    assert required.issubset(nets), f"missing networks: {required - nets}"


def test_compose_required_volumes_present(compose: dict) -> None:
    """AMD-09 / AMD-24: encrypted-at-rest volumes + audit-logs declared."""
    assert "volumes" in compose
    vols = set(compose["volumes"].keys())
    required = {"evidence-store", "pdf-cache", "audit-logs"}
    missing = required - vols
    assert not missing, f"missing volumes: {missing}"


# ─── Network isolation (REQ-CPL-036) ─────────────────────────────────────────


def _service_networks(svc: dict) -> set[str]:
    """Return the set of network names attached to a service.

    Compose `networks:` may be either a list ([net1, net2]) or a dict
    ({net1: {...}, net2: {...}}); handle both.
    """
    nets = svc.get("networks", [])
    if isinstance(nets, dict):
        return set(nets.keys())
    if isinstance(nets, list):
        return set(nets)
    return set()


def test_portal_net_and_public_net_share_no_services(compose: dict) -> None:
    """REQ-CPL-036: NO service may bridge portal-net and public-net.

    A service that joins both networks would let the public DSR portal reach
    redis/postgres, defeating the whole point of the isolation. Verifying via
    the static manifest is cheaper than runtime introspection and gives us a
    regression guard against future copy-paste mistakes.
    """
    portal_net_members: set[str] = set()
    public_net_members: set[str] = set()
    for name, svc in compose["services"].items():
        nets = _service_networks(svc)
        if "portal-net" in nets:
            portal_net_members.add(name)
        if "public-net" in nets:
            public_net_members.add(name)
    overlap = portal_net_members & public_net_members
    assert not overlap, (
        f"REQ-CPL-036 VIOLATION: services on BOTH portal-net AND public-net: "
        f"{overlap}. portal-net members: {portal_net_members}. "
        f"public-net members: {public_net_members}."
    )


def test_dsr_portal_only_on_public_net(compose: dict) -> None:
    """The public DSR portal MUST live exclusively on public-net."""
    nets = _service_networks(compose["services"]["dsr_portal"])
    assert nets == {"public-net"}, (
        f"dsr_portal must be on public-net only; found: {nets}"
    )


def test_portal_on_internal_mgmt_and_portal_net(compose: dict) -> None:
    """The internal portal lives on portal-net (data) + internal-mgmt (nginx)."""
    nets = _service_networks(compose["services"]["portal"])
    assert "portal-net" in nets, f"portal missing portal-net (have {nets})"
    assert "internal-mgmt" in nets, f"portal missing internal-mgmt (have {nets})"
    assert "public-net" not in nets, "portal must NOT be on public-net"


def test_redis_on_portal_net_only(compose: dict) -> None:
    """Redis is reachable from portal but never from dsr_portal."""
    nets = _service_networks(compose["services"]["redis"])
    assert nets == {"portal-net"}, f"redis networks: {nets}"


def test_public_nginx_only_on_public_net(compose: dict) -> None:
    """public_nginx must NOT be on portal-net (would create a bridge)."""
    nets = _service_networks(compose["services"]["public_nginx"])
    assert "portal-net" not in nets
    assert "internal-mgmt" not in nets
    assert "public-net" in nets


# ─── Port bindings ───────────────────────────────────────────────────────────


def test_nginx_ports_bound_to_localhost(compose: dict) -> None:
    """Both nginx services bind to 127.0.0.1 only (private-overlay isolation)."""
    for svc_name, expected_port in (
        ("portal_nginx", "8443"),
        ("public_nginx", "8444"),
    ):
        svc = compose["services"][svc_name]
        ports = svc.get("ports") or []
        assert ports, f"{svc_name} must declare ports"
        joined = " ".join(str(p) for p in ports)
        assert "127.0.0.1" in joined, (
            f"{svc_name} must bind to 127.0.0.1 (got {ports})"
        )
        assert expected_port in joined


def test_portal_and_dsr_portal_not_directly_published(compose: dict) -> None:
    """Application containers must not be PUBLICLY published — public access goes
    through nginx only. A loopback-only (127.0.0.1) mapping is permitted for
    local development; a public bind (0.0.0.0 / bare host port) is not."""
    for svc_name in ("portal", "dsr_portal"):
        svc = compose["services"][svc_name]
        for p in svc.get("ports") or []:
            joined = str(p)
            assert joined.startswith("127.0.0.1:"), (
                f"{svc_name} may only bind loopback (127.0.0.1) for local dev, "
                f"never publicly (got {p!r})"
            )


# ─── Secrets / env discipline (AMD-20) ───────────────────────────────────────


def test_compose_declares_required_secrets(compose: dict) -> None:
    """AMD-20: secrets are file-mounted, not env-string."""
    assert "secrets" in compose, "compose.yaml missing top-level secrets:"
    secrets = compose["secrets"]
    required = {"oidc_client_secret", "session_secret", "compliance_api_token"}
    missing = required - set(secrets.keys())
    assert not missing, f"missing top-level secrets: {missing}"
    # Every secret entry must be file-backed.
    for name, body in secrets.items():
        assert isinstance(body, dict)
        assert "file" in body, f"secret {name} not file-backed"


def test_portal_service_mounts_secrets(compose: dict) -> None:
    """Internal portal must mount its OIDC + session + API token secrets."""
    portal = compose["services"]["portal"]
    secrets = set(portal.get("secrets") or [])
    required = {"oidc_client_secret", "session_secret", "compliance_api_token"}
    missing = required - secrets
    assert not missing, f"portal missing secret mounts: {missing}"


# ─── Dockerfile invariants ───────────────────────────────────────────────────


def test_dockerfiles_exist() -> None:
    assert DOCKERFILE_PORTAL.is_file()
    assert DOCKERFILE_DSR.is_file()


def test_dockerfile_portal_runs_as_non_root() -> None:
    """REQ-CPL-001: container must run as uid 10001."""
    text = DOCKERFILE_PORTAL.read_text(encoding="utf-8")
    assert re.search(r"--uid\s+10001", text), "uid 10001 not declared"
    assert re.search(r"--gid\s+10001", text), "gid 10001 not declared"
    assert re.search(r"^USER\s+app:app", text, re.MULTILINE), "USER directive missing"


def test_dockerfile_dsr_runs_as_non_root() -> None:
    text = DOCKERFILE_DSR.read_text(encoding="utf-8")
    assert re.search(r"--uid\s+10001", text)
    assert re.search(r"--gid\s+10001", text)
    assert re.search(r"^USER\s+app:app", text, re.MULTILINE)


def test_dockerfiles_have_healthcheck() -> None:
    """Image-level HEALTHCHECK is required for both portals."""
    for path, port in ((DOCKERFILE_PORTAL, "8001"), (DOCKERFILE_DSR, "8002")):
        text = path.read_text(encoding="utf-8")
        assert "HEALTHCHECK" in text, f"{path.name} missing HEALTHCHECK"
        assert port in text, f"{path.name} missing port {port}"
        assert "/healthz" in text, f"{path.name} healthcheck not hitting /healthz"


def test_dockerfile_portal_uses_multistage() -> None:
    """REQ-CPL-001: multi-stage build (builder + runtime)."""
    text = DOCKERFILE_PORTAL.read_text(encoding="utf-8")
    stages = re.findall(r"^FROM\s+\S+\s+AS\s+(\w+)", text, re.MULTILINE)
    assert "builder" in stages and "runtime" in stages, f"stages: {stages}"


def test_dockerfile_includes_weasyprint_native_deps() -> None:
    """WeasyPrint requires libcairo2 + libpango-1.0-0 + libgdk-pixbuf-2.0-0."""
    for path in (DOCKERFILE_PORTAL, DOCKERFILE_DSR):
        text = path.read_text(encoding="utf-8")
        assert "libcairo2" in text, f"{path.name} missing libcairo2"
        assert "libpango" in text, f"{path.name} missing libpango"
        assert "libgdk-pixbuf" in text, f"{path.name} missing libgdk-pixbuf"


def test_dockerfile_uses_tini_as_pid1() -> None:
    """tini reaps zombies and forwards signals cleanly."""
    for path in (DOCKERFILE_PORTAL, DOCKERFILE_DSR):
        text = path.read_text(encoding="utf-8")
        assert "/usr/bin/tini" in text, f"{path.name} missing tini ENTRYPOINT"


# ─── entrypoint.sh (AMD-20) ──────────────────────────────────────────────────


def test_entrypoint_exists_and_executable() -> None:
    assert ENTRYPOINT.is_file()
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env sh") or text.startswith("#!/bin/sh")


def test_entrypoint_loads_secrets_from_run_secrets() -> None:
    """AMD-20: entrypoint sources file-mounted secrets under /run/secrets/."""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert "/run/secrets/" in text, "entrypoint not reading /run/secrets/"
    # Must export at least the named OIDC + session + compliance secrets.
    for name in ("oidc_client_secret", "session_secret", "compliance_api_token"):
        assert name in text, f"entrypoint missing handling of {name}"


def test_entrypoint_enforces_group_mapping_allowlist() -> None:
    """AMD-20: unknown OIDC_GROUP_* keys must be REJECTED, not silently dropped."""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    # Allowlist must enumerate the known keys and bail on unknown ones.
    for key in (
        "OIDC_GROUP_ADMIN",
        "OIDC_GROUP_COMPLIANCE_OFFICER",
        "OIDC_GROUP_AUDITOR",
        "OIDC_GROUP_SME",
        "OIDC_GROUP_VIEWER",
    ):
        assert key in text, f"entrypoint allowlist missing {key}"
    # Reject branch must exist
    assert "exit 1" in text and "unknown group_role_mapping" in text


def test_entrypoint_execs_command() -> None:
    """Final line must `exec "$@"` so PID 1 semantics are correct."""
    text = ENTRYPOINT.read_text(encoding="utf-8")
    assert 'exec "$@"' in text


# ─── nginx (AMD-11, AMD-21) ──────────────────────────────────────────────────


def test_internal_nginx_tls_pinning() -> None:
    """AMD-21: internal.conf pins TLS 1.2 + 1.3 and modern ciphers."""
    text = NGINX_INTERNAL.read_text(encoding="utf-8")
    assert "ssl_protocols       TLSv1.2 TLSv1.3" in text or \
           "ssl_protocols TLSv1.2 TLSv1.3" in text
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" in text
    assert "ssl_session_tickets off" in text


def test_public_nginx_body_size_amd11() -> None:
    """AMD-11: public.conf sets client_max_body_size 4m + buffer 128k."""
    text = NGINX_PUBLIC.read_text(encoding="utf-8")
    assert re.search(r"client_max_body_size\s+4m", text), \
        "public nginx must cap body at 4m (AMD-11)"
    assert re.search(r"client_body_buffer_size\s+128k", text), \
        "public nginx must set 128k body buffer (AMD-11)"


def test_public_nginx_tls_pinning() -> None:
    text = NGINX_PUBLIC.read_text(encoding="utf-8")
    assert "TLSv1.2 TLSv1.3" in text
    assert "ECDHE-ECDSA-AES256-GCM-SHA384" in text
    assert "ssl_session_tickets off" in text


def test_public_nginx_has_rate_limit_and_waf() -> None:
    """Public listener has tight rate limit + naive WAF."""
    text = NGINX_PUBLIC.read_text(encoding="utf-8")
    assert "limit_req_zone" in text
    assert "100r/m" in text, "public rate limit not 100r/m"
    assert "waf_bad_request_uri" in text, "WAF map missing"
    assert "X-Robots-Tag" in text
    assert "noindex" in text


def test_public_nginx_hsts() -> None:
    text = NGINX_PUBLIC.read_text(encoding="utf-8")
    assert "Strict-Transport-Security" in text


# ─── .dockerignore ───────────────────────────────────────────────────────────


def test_dockerignore_exists_and_excludes_sensitive_paths() -> None:
    assert DOCKERIGNORE.is_file()
    text = DOCKERIGNORE.read_text(encoding="utf-8")
    for pattern in (
        ".venv",
        ".git",
        "__pycache__",
        "tests",
        "docs",
        ".env",
        "conductor-state.json",
        "BRD-tracker.json",
        "docker/secrets/",
    ):
        assert pattern in text, f".dockerignore missing pattern: {pattern}"


# ─── Documentation ───────────────────────────────────────────────────────────


def test_docker_readme_documents_amd_09_and_24() -> None:
    """AMD-09 (encryption-at-rest) and AMD-24 (log forwarding) must be documented."""
    assert DOCKER_README.is_file()
    text = DOCKER_README.read_text(encoding="utf-8")
    # AMD-09: encryption-at-rest
    assert "Encryption At Rest" in text or "encryption at rest" in text.lower()
    assert "LUKS" in text or "FileVault" in text or "BitLocker" in text
    # AMD-24: log forwarding
    assert "Log Forwarding" in text or "log forwarding" in text.lower()
    assert "90" in text  # 90-day retention reference


def test_sbom_doc_describes_cyclonedx_and_syft() -> None:
    """AMD-22: SBOM generation step documented."""
    assert SBOM_DOC.is_file()
    text = SBOM_DOC.read_text(encoding="utf-8")
    assert "CycloneDX" in text
    assert "syft" in text


def test_secrets_example_dir_populated() -> None:
    """Placeholder secrets must exist so compose config validates."""
    assert SECRETS_EXAMPLE.is_dir()
    expected = (
        "oidc_client_secret.txt",
        "session_secret.txt",
        "compliance_service_token.txt",
        "db_password.txt",
        "README.md",
    )
    have = {p.name for p in SECRETS_EXAMPLE.iterdir()}
    missing = set(expected) - have
    assert not missing, f"missing example secrets: {missing}"


# ─── Module-level ASGI app exports (uvicorn discovery) ──────────────────────


def test_dsr_portal_has_module_level_app() -> None:
    """Uvicorn ENTRYPOINT discovers `dsr_portal.main:app` — must exist."""
    from dsr_portal.main import app as dsr_app
    from fastapi import FastAPI

    assert isinstance(dsr_app, FastAPI)
    assert dsr_app.title == "Public DSR Portal"


def test_portal_has_module_level_app() -> None:
    """Uvicorn ENTRYPOINT discovers `portal.main:app` — must exist."""
    from fastapi import FastAPI

    from portal.main import app as portal_app

    assert isinstance(portal_app, FastAPI)
    assert "internal" in portal_app.title.lower()
