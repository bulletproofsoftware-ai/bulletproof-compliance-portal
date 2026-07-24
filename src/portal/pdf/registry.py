"""Component registry for the generic /export/pdf/{component}/{document_id} route.

Each portal component (audit explorer, evidence package, gate decision, etc.)
registers a `(template, resolver, audit_event_type, ...)` tuple at app startup.
The router looks up the spec by component name, calls the resolver with the
document id + current user (RBAC enforced inside the resolver), and feeds the
returned context into PdfService.

Resolvers are async callables. They MUST raise:
  - `HTTPException(404)` when the document does not exist
  - `HTTPException(403)` when the user lacks permission for THIS document
    (auditor scope check, role check, project ACL check, etc.)

The registry is process-global. Tests get a fresh registry via
`PdfComponentRegistry()` and inject it into the router.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from ..auth.models import User
from .signature import SignatureSpec

# (template_name, jinja_context, document_title, classification)
ResolverResult = tuple[str, dict[str, Any], str, str]
ResolverFn = Callable[[str, User], Awaitable[ResolverResult]]
SignatureExtractorFn = Callable[[dict[str, Any]], SignatureSpec | None]
RequiresPadesFn = Callable[[dict[str, Any]], bool]


@dataclass(slots=True)
class ComponentSpec:
    """Registered PDF export configuration for a single portal component."""

    component: str
    template: str
    resolver: ResolverFn
    audit_event_type: str
    allowed_roles: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"admin", "compliance_officer", "auditor", "sme", "viewer"}
        )
    )
    auditor_only_components: bool = False
    """If True, viewers/SMEs CANNOT access (e.g., evidence packages — auditor scope)."""
    cache_ttl_s: int | None = None
    """Per-component TTL override; None means use global cache default."""
    requires_pades: RequiresPadesFn = field(default=lambda ctx: False)
    """Returns True iff this document requires AMD-08 byterange signing."""
    extract_signature: SignatureExtractorFn = field(default=lambda ctx: None)
    """Returns the body SignatureSpec already attached to the context, or None."""

    def is_role_allowed(self, role_value: str) -> bool:
        return role_value in self.allowed_roles


class PdfComponentRegistry:
    """Component spec lookup. Thread-safe under GIL — registration is
    one-shot at startup; reads are dict.get."""

    def __init__(self) -> None:
        self._specs: dict[str, ComponentSpec] = {}

    def register(
        self,
        component: str,
        *,
        template: str,
        resolver: ResolverFn,
        audit_event_type: str,
        allowed_roles: frozenset[str] | set[str] | None = None,
        auditor_only_components: bool = False,
        cache_ttl_s: int | None = None,
        requires_pades: RequiresPadesFn | None = None,
        extract_signature: SignatureExtractorFn | None = None,
    ) -> ComponentSpec:
        if not component or "/" in component or " " in component:
            raise ValueError(f"invalid component name: {component!r}")
        if not template:
            raise ValueError("template is required")
        if not callable(resolver):
            raise ValueError("resolver must be callable")
        if not audit_event_type:
            raise ValueError("audit_event_type is required")

        spec = ComponentSpec(
            component=component,
            template=template,
            resolver=resolver,
            audit_event_type=audit_event_type,
            allowed_roles=(
                frozenset(allowed_roles)
                if allowed_roles is not None
                else ComponentSpec.__dataclass_fields__["allowed_roles"].default_factory()  # type: ignore[union-attr]
            ),
            auditor_only_components=auditor_only_components,
            cache_ttl_s=cache_ttl_s,
            requires_pades=requires_pades or (lambda ctx: False),
            extract_signature=extract_signature or (lambda ctx: None),
        )
        if component in self._specs:
            raise ValueError(f"component already registered: {component!r}")
        self._specs[component] = spec
        return spec

    def unregister(self, component: str) -> bool:
        return self._specs.pop(component, None) is not None

    def get(self, component: str) -> ComponentSpec | None:
        return self._specs.get(component)

    def list_components(self) -> list[str]:
        return sorted(self._specs.keys())

    def __contains__(self, component: str) -> bool:
        return component in self._specs

    def __len__(self) -> int:
        return len(self._specs)


# ── Process-global default registry ─────────────────────────────────────────

_default_registry: PdfComponentRegistry | None = None


def get_default_registry() -> PdfComponentRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = PdfComponentRegistry()
    return _default_registry


def reset_default_registry() -> None:
    """Test helper — drop all registrations."""
    global _default_registry
    _default_registry = PdfComponentRegistry()


def register_component(
    component: str,
    *,
    template: str,
    resolver: ResolverFn,
    audit_event_type: str,
    allowed_roles: frozenset[str] | set[str] | None = None,
    auditor_only_components: bool = False,
    cache_ttl_s: int | None = None,
    requires_pades: RequiresPadesFn | None = None,
    extract_signature: SignatureExtractorFn | None = None,
) -> ComponentSpec:
    """Convenience — register on the default registry."""
    return get_default_registry().register(
        component,
        template=template,
        resolver=resolver,
        audit_event_type=audit_event_type,
        allowed_roles=allowed_roles,
        auditor_only_components=auditor_only_components,
        cache_ttl_s=cache_ttl_s,
        requires_pades=requires_pades,
        extract_signature=extract_signature,
    )


__all__ = [
    "ComponentSpec",
    "PdfComponentRegistry",
    "ResolverResult",
    "ResolverFn",
    "register_component",
    "get_default_registry",
    "reset_default_registry",
]
