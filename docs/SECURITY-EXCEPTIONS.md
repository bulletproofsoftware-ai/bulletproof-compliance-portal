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
| Practical impact | Degraded responsiveness **for all concurrent users of the portal worker**, not only the submitter — see below. No data disclosure, no privilege escalation, no integrity impact. |

> [!warning] Corrected blast radius (CISO condition C2)
> An earlier revision of this entry stated the impact was limited to "the portal
> they themselves use". **That was wrong and understated the risk.**
>
> `render_note()` is synchronous, CPU-bound work invoked directly inside `async def`
> request handlers with **no threadpool offload** — a repo-wide search for
> `run_in_threadpool`, `to_thread`, and `ThreadPool` returns nothing:
> - `src/portal/routers/incidents.py:286` (handler at `:274`)
> - `src/portal/routers/project_docs.py:429` and `:649`
>
> CPU time spent there blocks the worker's event loop, so slow rendering degrades
> **every concurrent request served by that worker**, not just the request that
> caused it.
>
> This does not change the acceptance decision — the vulnerable email path is still
> unreachable — but the exposure statement must be accurate about what *would*
> happen if it ever became reachable, or if the reachable rendering path itself is
> fed pathological input.

The attacker who can reach this code path is a trusted, named, authenticated user.
That constrains likelihood and gives full attribution; it does not constrain blast
radius, which is worker-wide.

### Compensating controls

- **A hard 10,000-character input cap on incident notes** —
  `src/portal/routers/incidents.py:277`,
  `content: str = Form(..., min_length=1, max_length=10_000)`. This is the single
  strongest control on this path: it bounds the reachable render pipeline to
  roughly 27 ms of work. Removing or raising this cap materially changes the risk
  and requires security review.
- `slowapi` rate limiting, applied **globally** via `SlowAPIMiddleware`
  (`src/portal/main.py:249`, `src/dsr_portal/main.py:173`). There are no per-route
  `@limiter.limit(...)` decorators anywhere in the codebase; coverage comes from a
  single default limit that every route falls through to. Keying is on the real
  client IP because `ForwardedHeaderMiddleware` is registered last and therefore
  runs first (`src/portal/main.py:258`).
- The public, unauthenticated attack surface (DSR portal) is architecturally
  separate and does not import this code.
- The markdown pipeline runs `markdown-it-py` with `html=False`, so raw HTML
  never becomes DOM nodes before sanitization.
- All portal access is authenticated and attributable via OIDC.

> [!note] Known gap, not a blocker for this exception
> `doc.content` rendered at `project_docs.py:429` and `:649` has **no equivalent
> size cap**. That content originates from the compliance service rather than
> direct user input, so it is not attacker-controlled in the same way — but the
> reachable render pipeline is superlinear in input size, and a cap plus
> `run_in_threadpool` offload would be prudent hardening. Tracked as a
> recommendation, not a condition of this exception.

### Review

| Date | Reviewer | Outcome |
|---|---|---|
| 2026-07-27 | CISO review | **APPROVE WITH CONDITIONS** |

The reviewer independently verified the unreachability argument rather than
accepting it: confirmed `parse_email=False` defaults in installed bleach 6.4.0
(`bleach/__init__.py:85`, `linkifier.py:109`, `:210`), confirmed
`handle_email_addresses()` has exactly one call site guarded by
`if self.parse_email:` (`linkifier.py:618-619`), and confirmed zero
`parse_email` occurrences in `src/`. Benchmarked the vulnerable path at
**1.29 s enabled vs 0.0023 s in this configuration** (~560×) at the 10,000-char
cap, with quadratic scaling. Also confirmed `src/dsr_portal/` has zero
references to bleach/markdown rendering.

**Conditions and status:**

| # | Condition | Status |
|---|---|---|
| C1 | Replace the prose guard with an enforceable control | **DONE** — `tests/test_markdown_render_guard.py` (9 tests) + named CI step in `.github/workflows/ci.yml`. Verified to FAIL when `parse_email=True` is injected. |
| C2 | Correct the impact statement; add the 10,000-char cap to controls | **DONE** — see the corrected blast-radius callout above. |
| C3 | Fix `rate_limit.py` docstring; fix the discarded async 429 handler | **DONE** — docstring now describes the actual global-default mechanism; `_rate_limit_handler` made synchronous so the custom body is no longer dead code. |
| C4 | Fix the `markdown_render.py` linkify comment | **DONE** — comment corrected and a security note added covering the `linkify-it-py` / `fuzzy_email=True` trap. |
| C5 | Regenerate the SBOM against the actual pinned set | **OPEN** — blocking for release, not for this exception. See below. |

**Retirement conditions.** This exception is void if any of the following occur:
1. bleach publishes a release addressing the ReDoS (upgrade instead);
2. `parse_email=True` is introduced anywhere in `src/`;
3. the markdown-it `linkify` rule is enabled, or `linkify-it-py` enters the
   dependency set (its `fuzzy_email=True` default reintroduces the same risk).

Conditions 2 and 3 are enforced by `tests/test_markdown_render_guard.py`, not by
this document.

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
