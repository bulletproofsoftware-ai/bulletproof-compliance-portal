# Security Scan Report — bulletproof-compliance-portal

This report summarises the Code Hardener `standard`-profile security scan of the
compliance portal at the commit that ships this document. It is the human-readable
companion to the signed artifacts in this directory.

## Result

| Field | Value |
|-------|-------|
| Scanner | Code Hardener (`standard` profile, 12 tools) |
| Branch | `main` |
| Score | **908 / 1000** |
| Critical findings | **0** |
| High findings | **0** |
| Medium findings | 19 (residual, low-risk — see below) |
| Low findings | 11 (residual, low-risk — see below) |
| Secret scan (gitleaks) | **PASS** — no secrets detected |
| Attestation | Ed25519-signed, in-toto (`attestation.json`) |

The `standard` profile runs 12 code-appropriate scanners: **trivy, grype, syft,
gitleaks, opengrep, checkov, oxlint, ruff, bandit, dockle, hadolint** and the
CycloneDX/SBOM generator.

## Fixes applied to reach 0 critical / 0 high

The first scan reported **4 critical** and **24 high** findings (each dependency
CVE is reported by both trivy and grype, so the unique counts are lower). Every
one was remediated before this report was published; the re-scan below confirms
zero.

### Dependency CVEs — bumped to the advisory's first patched version

| Package | From | To | Severity | Advisories fixed |
|---------|------|----|----------|------------------|
| python-jose | 3.3.0 | 3.5.0 | CRITICAL | CVE-2024-33663 (ECDSA/OpenSSH key algorithm confusion), CVE-2024-29370, CVE-2024-33664 |
| authlib | 1.3.2 | 1.7.2 | CRITICAL + HIGH | CVE-2026-27962 (JWK header-injection auth bypass), CVE-2026-28498 (forged OIDC ID tokens), CVE-2026-28490 (JWE RSA1_5 padding oracle), CVE-2025-61920, CVE-2025-59420 |
| cryptography | 43.0.3 | 49.0.0 | HIGH | GHSA-537c-gmf6-5ccf (vulnerable bundled OpenSSL), CVE-2026-26007 (SECT-curve subgroup attack) |
| starlette | 0.41.2 | 1.3.1 | HIGH | CVE-2026-54283 (form-limit DoS), CVE-2026-48818 (StaticFiles UNC SSRF), CVE-2025-62727 (Range-header DoS) |
| orjson | 3.10.10 | 3.11.9 | HIGH | CVE-2025-67221 (deeply-nested-JSON recursion DoS) |
| python-multipart | 0.0.17 | 0.0.31 | HIGH | GHSA-5rvq-cxj2-64vf (quadratic querystring parsing DoS), GHSA-pp6c-gr5w-3c5g (unbounded multipart-header DoS) + three parameter-smuggling advisories |
| fastapi | 0.115.4 | 0.140.0 | — | Required so starlette 1.3.1 is permitted (FastAPI < 0.135 caps starlette below the patched line). No CVE of its own. |

### Code lints — behaviour-preserving refactors (opengrep/ruff HIGH `SIM` family)

| Rule | File | Fix |
|------|------|-----|
| SIM103 | `src/portal/auth/mfa.py` | Return the boolean comparison directly instead of `if …: return False` / `return True` |
| SIM109 | `src/portal/middleware/audit.py` | Drop a duplicated `path == e` equality term |
| SIM102 | `src/portal/routers/dsr.py` | Collapse a nested guard into one `if` |
| SIM102 | `src/portal/routers/export.py` | Collapse a nested guard into one `if` |
| SIM105 | `src/portal/routers/{audit,gates,model_cards,reports}.py` | Best-effort audit `try/except/pass` → `contextlib.suppress(Exception)` (5 sites) |

### Framework-compatibility fixes (from the FastAPI/Starlette major bump)

- `src/portal/routers/process_knowledge.py` — the batch endpoint now accepts an
  empty `candidate_ids` form value so it still returns its documented **400**
  ("no candidate_ids provided"). Starlette ≥ 1.0 rejects empty values for
  required form fields with a framework **422** before the handler body runs.
- `tests/test_root_redirect.py` — traverses `_IncludedRouter.original_router`
  because FastAPI ≥ 0.135 no longer flattens included routes onto `app.routes`.

All fixes were verified: both the internal and public FastAPI apps import cleanly,
and 555 of 556 tests pass. (The single failure, `test_rejects_wrong_secret`, is a
**pre-existing** test bug unrelated to any change here — it signs and verifies a
webhook payload with the *same* secret and then asserts the signature is rejected;
it fails identically on the original dependency set.)

## What remains (low-risk, residual)

Per policy, medium and low findings are documented honestly rather than forced to
zero. None are critical or high.

**Medium (19):**

- `RUFF-F401` (11) — unused imports. Cosmetic; left in place because automated
  import-stripping can remove defensive/re-export imports. Safe to prune manually.
- `github-actions-mutable-action-tag` (2) — GitHub Actions referenced by a
  mutable tag rather than a pinned commit SHA in the CI workflow.
- Dependency CVEs, all MODERATE and easily addressed in a follow-up patch bump:
  jinja2 3.1.4 (CVE-2024-56201 / CVE-2024-56326 / CVE-2025-27516 → fixed in
  3.1.6), weasyprint 68.1 (CVE-2026-49452), bleach 6.1.0 (GHSA-gj48-438w-jh9v),
  and the dev-only pytest 8.3.3 (CVE-2025-71176).

**Low (11):**

- `SBOM-LICENSE-UNKNOWN` (10) — the SBOM tool could not auto-classify a license
  string for a handful of components; the licenses are documented in
  [`../SBOM.md`](../SBOM.md) and [`../../THIRD_PARTY_LICENSES.md`](../../THIRD_PARTY_LICENSES.md).
- One MODERATE/LOW transitive advisory (GHSA-8rfp-98v4-mmr6).

## Artifacts

| File | Description |
|------|-------------|
| [`bulletproof-compliance-portal-scan-report.pdf`](bulletproof-compliance-portal-scan-report.pdf) | Rich portal report (12 pp). Page 1 is the Ed25519 attestation certificate + score. |
| [`scan-report-full.md`](scan-report-full.md) | Full machine-generated markdown report (all findings). |
| [`scan-report.sarif.json`](scan-report.sarif.json) | SARIF 2.1.0 for CI/code-scanning ingestion. |
| [`attestation.json`](attestation.json) | in-toto attestation, Ed25519-signed by the local signing key. |

Scanner-internal paths (`/scan-target/`) have been normalised out of the SARIF
and full-markdown artifacts; no host filesystem paths appear in this directory.

---

Apache-2.0 © 2026 bulletproofsoftware-ai. See [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
