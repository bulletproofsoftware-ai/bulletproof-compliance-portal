# Security Updates & End-of-Life Policy

This document describes when Compliance Portal versions stop receiving security updates and the upgrade path for unsupported versions.

## Table of Contents

1. [Overview](#overview)
2. [Security Update Timeline](#security-update-timeline)
3. [Version Support Matrix](#version-support-matrix)
4. [End-of-Life Process](#end-of-life-process)
5. [Security Update Severity](#security-update-severity)
6. [Upgrade Guidance](#upgrade-guidance)

## Overview

Security updates are the highest priority for Compliance Portal maintenance. Every supported version receives:

- **Critical CVEs**: Patch released within 24 hours
- **High CVEs**: Patch released within 7 days
- **Medium CVEs**: Patch released within 30 days
- **Low CVEs**: Included in next scheduled release

Once a version reaches **End of Life (EOL)**, it no longer receives any updates, including security patches.

### Support Status Terminology

| Status | Definition | Security Updates |
|--------|------------|------------------|
| **Active** | Current version with regular updates | Yes (all severities) |
| **Maintenance** | Previous major version | Yes (critical/high only) |
| **Security Only** | Older version before EOL | Yes (critical only) |
| **End of Life (EOL)** | Version no longer supported | No |

## Security Update Timeline

### Critical CVEs (9.0-10.0 CVSS)

**Examples**: Remote code execution, authentication bypass, data breach

**Patch Timeline**:
- **Discovery**: CVE published
- **0-4 hours**: Compliance Portal team assesses impact
- **4-24 hours**: Patch developed, tested, released

**Patch availability**:
- **Active versions**: Immediate hotfix
- **Maintenance versions**: Within 24 hours
- **Security-only versions**: Within 24 hours
- **EOL versions**: No patch (upgrade required)

**Example critical CVE**:

```
2024-04-27 09:00 UTC — CVE-2024-XXXXX published
  Remote Code Execution in FastAPI
  CVSS: 9.1 (Critical)
  Affected: FastAPI 0.115.0-0.115.3
  
2024-04-27 10:00 UTC — Compliance Portal assessment
  "We pinned FastAPI to 0.115.4 in requirements.txt
   Our users are NOT affected by this CVE
   Notification: Green light — no action needed"
  
OR
  
2024-04-27 10:00 UTC — Compliance Portal assessment
  "We use affected version. Begin hotfix immediately."
  
2024-04-27 14:00 UTC — Hotfix released
  "Compliance Portal 0.1.0-hotfix1 released
   - Updated FastAPI to 0.115.5 (includes CVE patch)
   - No application code changes
   - Zero-downtime rollout available"
```

### High CVEs (7.0-8.9 CVSS)

**Examples**: Privilege escalation, authentication weakness, sensitive data exposure

**Patch Timeline**:
- **Discovery**: CVE published
- **0-8 hours**: Assess impact
- **8 hours-7 days**: Develop, test, release patch

**Example high CVE**:

```
2024-04-27 09:00 UTC — CVE-2024-YYYYY published
  Authentication Bypass in OIDC library
  CVSS: 7.3 (High)
  
2024-04-27 16:00 UTC — Patch released
  Compliance Portal 0.1.1 (regular patch release)
  - Updated python-jose to fixed version
  - Enhanced OIDC nonce validation
  - Recommend upgrade within 7 days
```

### Medium CVEs (4.0-6.9 CVSS)

**Examples**: Information disclosure, denial of service, insecure defaults

**Patch Timeline**:
- **Discovery**: CVE published
- **0-24 hours**: Assess impact
- **1-30 days**: Develop, test, release patch

**Usually included in**:
- Next scheduled patch release (e.g., 0.1.2, 0.1.3)
- Not treated as hotfix unless it affects many users

### Low CVEs (0.1-3.9 CVSS)

**Examples**: Weak defaults, best practice violations

**Patch Timeline**:
- Included in next scheduled release
- Not expedited

## Version Support Matrix

### Beta Versions (0.x.x)

| Version | Released | Support Ends | Security Ends | Status |
|---------|----------|--------------|---------------|--------|
| **0.1.x** | 2024-04-27 | 2024-10-27 | 2024-12-31 | Active |
| **0.2.x** | TBD | TBD | TBD | Not released |

**Beta characteristics**:
- Breaking changes may occur between minor versions
- 6-month support window
- 8-month security window (2 months past support)
- Recommended for: Development, testing, non-production

### Production Versions (1.x+)

| Version | Released | Support Ends | Security Ends | Status |
|---------|----------|--------------|---------------|--------|
| **1.0.x** | TBD | TBD | TBD | Not released |
| **1.1.x** | TBD | TBD | TBD | Not released |
| **2.0.x** | TBD | TBD | TBD | Not released |

**Production characteristics**:
- Semantic versioning (major.minor.patch)
- 2-year support for each major version
- Major version overlap: Support overlaps by 6 months
- Recommended for: All production environments

### Support Matrix Example

```
Timeline for versions 1.0 → 2.0 → 3.0 release:

2024-08-01: Release 1.0.0 (2-year support)
  └─ Support ends: 2026-08-01
  └─ Security ends: 2026-08-01 (same for 1.x)

2025-06-01: Release 1.5.0 (within 1.x lifecycle)
  └─ Part of 1.x support
  └─ Support ends: 2026-08-01

2026-08-01: Release 2.0.0 (2-year support)
  └─ 1.x EOL begins
  └─ 1.x moves to "security-only" status (wait, 1.x already ended)
  └─ Actually: 1.x is now EOL, no more updates
  └─ 2.x support ends: 2028-08-01

2028-08-01: Release 3.0.0 (2-year support)
  └─ 2.x EOL begins
  └─ 3.x support ends: 2030-08-01
```

## End-of-Life Process

### Pre-EOL Notifications

Users receive multiple notifications before a version reaches EOL:

#### 120 Days Before EOL
```
Subject: Compliance Portal Version 0.1.x reaches EOL in 120 days

Dear Compliance Portal users,

Version 0.1.x will reach End-of-Life on 2024-10-27 and will no longer
receive updates, including security patches.

We recommend upgrading to a supported version:
- Version 1.0.x (recommended for production)
- Version 0.2.x (recommended for development)

Migration guides:
- From 0.1.x to 1.0.x: docs/UPGRADE-0.1-to-1.0.md
- From 0.1.x to 0.2.x: docs/UPGRADE-0.1-to-0.2.md

Support team is available to assist with upgrades:
- Email: support@acme.io
- GitHub Discussions: /compliance-portal/discussions
```

#### 60 Days Before EOL
```
Subject: URGENT: Upgrade Compliance Portal before 2024-10-27

Version 0.1.x reaches EOL in 60 days. After that date:
- No security patches
- No bug fixes
- No support

Take action now: Follow upgrade guide and test in staging environment.
Questions? Email support@acme.io
```

#### 30 Days Before EOL
```
Subject: CRITICAL: Only 30 days until Compliance Portal 0.1.x EOL

Time is running out! Version 0.1.x becomes unsupported on 2024-10-27.

Next steps:
1. Review upgrade guide (docs/UPGRADE-0.1-to-1.0.md)
2. Upgrade to version 1.0.x
3. Run full test suite
4. Deploy to production
5. Verify all features work

Blocked? Email support@acme.io for upgrade assistance.
```

#### 10 Days Before EOL
```
Subject: WARNING: 10 days until Compliance Portal 0.1.x is unsupported

Urgent reminder: Upgrade immediately to avoid security risks!

Still need help? Call support team for emergency upgrade assistance.
```

#### EOL Day
```
Subject: Compliance Portal 0.1.x is now End-of-Life

As of today (2024-10-27), version 0.1.x is no longer supported.

If you're still running 0.1.x:
- SECURITY RISK: No patches for vulnerabilities
- UPDATE REQUIRED: Upgrade to 1.0.x as soon as possible
- EMERGENCY SUPPORT: Limited help available

Urgent upgrades: Contact support@acme.io
```

### Post-EOL Support

After EOL, support is **no longer provided**:

- **Bug reports**: Will not be fixed (recommend upgrade)
- **Security reports**: Will not be patched (recommend upgrade)
- **Questions**: Limited to "how do I upgrade" only

**Exception**: Critical security vulnerabilities in your deployment environment may be addressed if they also affect newer versions.

## Security Update Severity

### CVSS Scoring

Security vulnerabilities are scored using CVSS (Common Vulnerability Scoring System) version 3.1:

| CVSS Score | Severity | Response |
|-----------|----------|----------|
| 0.0 | None | Informational |
| 0.1-3.9 | Low | Include in next release |
| 4.0-6.9 | Medium | Patch within 30 days |
| 7.0-8.9 | High | Patch within 7 days |
| 9.0-10.0 | Critical | Patch within 24 hours |

### CVE Notifications

When a CVE is published for a Compliance Portal dependency:

1. **Automated scanning** detects it (pip-audit, Trivy)
2. **Compliance Portal team** assesses impact
3. **Decision**: Is Compliance Portal affected?
   - **NO**: Green light — users are safe, no action needed
   - **YES**: Begin patching process

4. **Notification sent** to all users:
   ```
   ✅ GREEN: CVE-XXXX does not affect Compliance Portal users
   ⚠️ YELLOW: CVE-XXXX found; patch available in version Y.Z
   🔴 RED: CVE-XXXX is critical; hotfix released immediately
   ```

## Upgrade Guidance

### Upgrade Path Recommendations

| Current Version | Recommended Upgrade | Effort | Downtime |
|-----------------|-------------------|--------|----------|
| 0.1.x | 1.0.x | Low (1-2 hours) | 0 min (rolling) |
| 1.0.x | 1.1.x | Very low (none) | 0 min |
| 1.0.x | 2.0.x | Medium (1-2 days) | Possible (breaking changes) |
| 0.1.x (EOL) | 1.0.x | Medium (2-4 hours) | 0 min (rolling) |
| 1.0.x (EOL) | 2.0.x | High (1+ weeks) | Plan maintenance window |

### Urgent Upgrade (After EOL)

If you're on an EOL version and a critical CVE is published:

```bash
# 1. Immediate: Disable public access to mitigate
kubectl scale deployment/compliance-portal --replicas=0
# Public access via WAF/firewall redirects to maintenance page

# 2. Start upgrade process (see INSTALLATION.md)
# Follow fast-track upgrade procedure

# 3. Deploy new version
kubectl set image deployment/compliance-portal portal=compliance-portal:v1.0.0

# 4. Restore public access
kubectl scale deployment/compliance-portal --replicas=3
```

### Staying Current

Best practices to avoid EOL issues:

1. **Subscribe to notifications** (check your email settings)
2. **Plan upgrades quarterly** (don't wait until EOL)
3. **Test in staging first** (never upgrade production blind)
4. **Join the community** (GitHub Discussions for upgrade tips)
5. **Set calendar reminders** (EOL dates listed above)

### Support During Upgrade

If you need help upgrading:

1. **Check upgrade guide** (docs/UPGRADE-*.md)
2. **Ask in GitHub Discussions**
3. **Email support@acme.io**
4. **For urgent help**: Purchase commercial support

## Security-Related CVEs vs Compliance-Related Issues

### Security CVE (Software Vulnerability)

CVEs in dependencies or code:

```
CVE-2024-XXXXX: Remote code execution in FastAPI
CVSS: 9.1 (Critical)
Impact: Attacker can execute code on portal server
Response: Hotfix released in < 24 hours
```

**Action**: Upgrade immediately to patched version

### Compliance Issue (Not a CVE)

Non-security compliance findings:

```
ISO 27001 Audit Finding: Audit log rotation not configured
Impact: Audit logs may grow unbounded
Response: Configuration change; no code patch needed
```

**Action**: Update configuration; no version upgrade needed

Most security-related items are CVEs (software vulnerabilities), not compliance issues. Compliance issues are addressed through configuration, procedures, or operational controls.

## Related Documents

- **SECURITY.md** — Vulnerability reporting procedures
- **CHANGELOG.md** — Version history
- **SUPPORT-POLICY.md** — Overall support policy
- **INSTALLATION.md** — Deployment and upgrade procedures
