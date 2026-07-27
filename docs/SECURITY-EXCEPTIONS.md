# Security Exceptions Register

Accepted-risk records for findings that cannot be remediated by a dependency
upgrade. Every entry states the finding, why no fix exists, the exposure
analysis, the compensating controls, and the condition that retires the
exception.

An entry here is **not** a permanent waiver. Each is re-evaluated whenever the
upstream package publishes a release, and at minimum each quarter.

---

## SEC-EX-001 — `bleach` ReDoS (no upstream fix)

| Field | Value |
|---|---|
| **Status** | Accepted — **NOT EXPLOITABLE in this codebase** |
| **Opened** | 2026-07-27 |
| **Severity** | Medium (CVSS 5.3, CVSS v4.0) |
| **Package** | `bleach==6.4.0` |
| **Finding** | Regular Expression Denial of Service (ReDoS) |
| **Advisory** | [SNYK-PYTHON-BLEACH-17356127](https://security.snyk.io/vuln/SNYK-PYTHON-BLEACH-17356127) |
| **Vulnerable function** | `LinkifyFilter.handle_email_addresses()` |
| **Trigger condition** | **requires `parse_email=True`** |
| **Scanner** | Snyk (`snyk test`, isolated venv) |
| **`fixedIn`** | **NONE** — no patched release exists |
| **Retires when** | bleach publishes a release addressing the ReDoS |

### The vulnerable code path is never reached

Per the Snyk advisory, the ReDoS lives in `LinkifyFilter.handle_email_addresses()`
and is only reachable when the caller opts into email parsing via `parse_email=True`.

`parse_email` defaults to `False`:

```
bleach.linkify(text, callbacks=[...], skip_tags=None, parse_email=False)
LinkifyFilter.__init__  parse_email default: False
```

Both call sites in this repository invoke linkify without that argument:

- `src/portal/services/markdown_render.py:95` → `bleach.linkify(cleaned, callbacks=[nofollow])`
- `src/portal/services/project_docs.py:74`    → `bleach.linkify(cleaned, callbacks=[nofollow])`

A repository-wide search for `parse_email` returns no matches outside this
document. **`handle_email_addresses()` is therefore never invoked, and the
vulnerable regex is never evaluated.** This is unreachable code, not merely
low-likelihood exploitation.

> [!important] Regression guard
> This exception depends on `parse_email` remaining `False`. If any future
> change passes `parse_email=True` to `bleach.linkify`, this finding becomes
> live and this exception is void. Treat `parse_email=True` as a change
> requiring security review.

### Why it cannot be fixed by upgrade

`6.4.0` is the current release (published 2026-06-05) and carries the finding.
Snyk reports `fixedIn: NONE` — there is no version to move to.

> Correction to an earlier assessment: bleach is **not** abandoned. Releases
> shipped 6.1.0 (2023-10), 6.2.0 (2024-10), 6.3.0 (2025-10), 6.4.0 (2026-06).
> An upstream fix is plausible, which is why this is an exception with a
> retirement condition rather than a migration.

### Why we are not replacing bleach with `nh3`

1. **`src/portal/services/markdown_render.py` is a designated security control
   surface.** Its module docstring states it "MUST NOT be modified ... without
   an explicit CISO amendment update". Swapping the sanitizer is precisely such
   a modification.
2. **`nh3` (Ammonia) has different sanitization semantics.** It is not a
   drop-in substitute for `bleach.clean` + `bleach.linkify` + the `nofollow`
   callback. Divergence in an XSS control surface risks introducing an XSS
   hole — a materially worse outcome than the DoS being avoided.
3. **The trade is unfavourable**: accepting a low-exposure, authenticated-only
   DoS is preferable to risking XSS regression in a compliance portal.

### Exposure analysis

| Question | Finding |
|---|---|
| Reachable from the public DSR portal? | **No.** `src/dsr_portal/` contains no reference to `bleach`, `markdown_render`, or `render_note`. |
| Reachable anonymously? | **No.** Only the internal portal, which is OIDC-authenticated (Authentik IdP) across 5 roles: admin, compliance_officer, auditor, sme, viewer. |
| Who can trigger it? | An authenticated internal user submitting crafted markdown (e.g. WI-10 incident investigation notes). |
| Practical impact | An authenticated staff member could degrade responsiveness of the portal they themselves use. No data disclosure, no privilege escalation, no integrity impact. |

The attacker who can reach this code path is already a trusted, named,
authenticated user — the same user who could simply stop using the portal.

### Compensating controls

- `slowapi` rate limiting is present in the dependency set and applied to
  portal routes.
- The public, unauthenticated attack surface (DSR portal) is architecturally
  separate and does not import this code.
- The markdown pipeline runs `markdown-it-py` with `html=False`, so raw HTML
  never becomes DOM nodes before sanitization.
- All portal access is authenticated and attributable via OIDC.

### Review

| Date | Reviewer | Outcome |
|---|---|---|
| 2026-07-27 | Pending CISO sign-off | Proposed acceptance — awaiting review |

**Action for reviewer:** confirm acceptance, or direct migration to `nh3` with
a CISO amendment covering the control-surface change and an adversarial
re-test of the XSS cases enumerated in `markdown_render.render_note`'s
docstring.

---

## SEC-EX-002 — `torch` / `transformers` deserialization (separate repo)

Recorded here only as a cross-reference. These findings belong to
`bulletproof-process-knowledge-mcp`, not this repository.

| Field | Value |
|---|---|
| **Status** | Accepted (documented in that repo) |
| **Packages** | `torch==2.13.0`, `transformers==5.14.1` via `sentence-transformers` |
| **Findings** | 13 (8 HIGH, 5 MEDIUM) — Deserialization of Untrusted Data, Arbitrary Code Injection |
| **`fixedIn`** | **NONE** — present in the newest releases |

These are inherent pickle/model-loading risks in the ML stack, not defects with
patches. Mitigations: load models only from trusted sources, prefer
`safetensors` over pickle formats, set `weights_only=True` on `torch.load`.

---

*Maintained as part of the Snyk remediation programme. See the audit report in
Obsidian: `Projects/Bulletproof/2026-07-27-snyk-vulnerability-audit-report.md`.*
