# Security Policy

This document describes how to report security vulnerabilities in the **compliance-portal** project (PRD-19) and the response and disclosure commitments of the maintainers.

> Created per CISO Architecture Review AMD-23 (finding M-14 — vulnerability disclosure & patching SLA).

## Supported Versions

| Version Range | Supported |
|---------------|-----------|
| `0.1.x` (initial release line) | Yes — receives security fixes |
| Any pre-release / branch builds | No — use only for testing |

When a new minor or major release ships, the previous minor remains supported for 90 days for security fixes only. New features land on the current line.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts users at risk.

### Preferred Channel: Encrypted Email

Send vulnerability reports to:

- **Email**: `security@<your-domain>` (replace with the deployed organization's security contact at deployment time)
- **PGP Key**: see "PGP Key" section below

Include the following in your report:

1. **Affected component** — which spec / module / route is affected (e.g., `WI-09 public DSR portal`, `WI-19 PDF export service`)
2. **Vulnerability class** — e.g., SSRF, XSS, RCE, IDOR, auth bypass, privilege escalation, information disclosure
3. **Impact** — what an adversary can achieve (data exfiltration, account takeover, denial of service, etc.)
4. **Reproduction steps** — minimal proof-of-concept that demonstrates the issue without causing harm to production data
5. **Affected version(s)** — git SHA, image tag, or release tag
6. **Suggested mitigation** (optional) — if you have a proposed fix
7. **Your contact details** — name and channel for follow-up; you may report anonymously, but we cannot acknowledge or credit anonymous reports

### Acknowledgement & Credit

We aim to acknowledge receipt within **24 hours** of a report (see SLA below). Reporters who follow this disclosure policy will be credited in the release notes for the fix unless they request anonymity.

## Response Service-Level Agreements (SLAs)

| Phase | Target |
|-------|--------|
| **Acknowledgement of report** | 24 hours from receipt |
| **Initial triage and severity assignment** | 72 hours |
| **CRITICAL fix landed and released** | 30 days from triage |
| **HIGH fix landed and released** | 60 days from triage |
| **MEDIUM fix landed and released** | 90 days from triage |
| **LOW / informational** | Best-effort; no SLA |
| **Public disclosure (advisory + release notes)** | After fix is available; coordinated with reporter |

### Severity Definitions

- **CRITICAL** — Remote unauthenticated code execution; full compromise of integrity, confidentiality, or availability; mass exfiltration of PII or audit data; bypass of audit chain integrity.
- **HIGH** — Authenticated privilege escalation; bypass of RBAC / SoD enforcement; targeted information disclosure of confidential or restricted data; denial of service against the public DSR portal or audit chain verification path.
- **MEDIUM** — Information disclosure of internal-classification data, persistent XSS in authenticated-only views, weakened cryptographic posture, or a defence-in-depth control failure that does not by itself enable attack.
- **LOW** — Best-practice gaps with no exploitable path, hygiene findings, or hardening opportunities.

These map to the severity classes used in the CISO Architecture Review (`docs/CISO-architecture-review.md`).

## Patching and Disclosure Process

1. **Receipt** — Reporter sends encrypted email; security team acknowledges within 24h.
2. **Triage** — Security team reproduces, assigns severity, files internal tracking issue.
3. **Fix development** — Patch developed against the current release line; backported to supported lines if applicable.
4. **Pre-disclosure coordination** — Reporter is notified of the fix timeline; if external dependencies (e.g., upstream library) require coordination, this is communicated.
5. **Release** — Patched release published; release notes credit the reporter (unless anonymity requested).
6. **Public advisory** — A SECURITY ADVISORY is published in the repository and via any project mailing list / channel within 14 days of the patched release.

We support [coordinated vulnerability disclosure](https://www.cert.org/vulnerability-analysis/vul-disclosure.cfm). We will not pursue legal action against researchers acting in good faith and following this policy.

## PGP Key

The security team's PGP public key is below. Use it to encrypt your vulnerability report.

> NOTE TO OPERATOR: Replace this placeholder with the actual armored public key block at deployment time. The fingerprint and key block below are placeholders and MUST be replaced before the project is exposed externally.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

[PLACEHOLDER — replace with armored public key at deployment time.
The deployment runbook (deploy/README.md) includes the procedure for
generating and publishing this key. Until replaced, encrypted reports
cannot be received; report-via-PGP recipients should fall back to a
signal channel agreed out-of-band with the security team.]

-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint**: `XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX` (placeholder — replace at deployment time)

When the placeholder is replaced, also publish the fingerprint via:

- An out-of-band signed announcement (project blog, signed release notes)
- Multiple key servers (`keys.openpgp.org`, `keyserver.ubuntu.com`)

## Out-of-Scope

The following findings are NOT considered security vulnerabilities for the purposes of this policy:

- Reports against pre-release / branch / forked builds
- Findings that require physical access to the host
- Vulnerabilities in dependencies for which a public CVE already exists and is being tracked through the dependency-update workflow
- Social-engineering or phishing scenarios that do not exploit a software flaw
- Self-XSS that requires the victim to paste attacker-supplied JavaScript into their own browser console
- Missing security headers on out-of-scope endpoints (e.g., third-party-hosted documentation)
- Bug-bounty-style findings that produce duplicate reports already publicly tracked

## Hall of Fame

Reporters who follow this policy and contribute to the security of the compliance portal will be acknowledged here (with their permission):

- _(no entries yet — be the first!)_

## Related Documents

- `docs/CISO-architecture-review.md` — full security architecture review including STRIDE / OWASP / compliance framework mapping
- `docs/CISO-amendments-applied.md` — record of amendments applied to specs from the CISO review
- `deploy/README.md` — operator runbook including secret rotation, encryption-at-rest verification, log retention, SBOM management
- `BRD-tracker.json` — requirement traceability with security-relevant acceptance criteria

---

_This SECURITY.md was established 2026-04-27 per AMD-23 of the CISO Architecture Security Review. Last updated: 2026-04-27._
