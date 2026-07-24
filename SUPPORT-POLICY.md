# Support Policy

This document describes the scope and duration of support for Compliance Portal users.

## Table of Contents

1. [Overview](#overview)
2. [Supported Versions](#supported-versions)
3. [Support Scope](#support-scope)
4. [Support Lifecycle](#support-lifecycle)
5. [Security Update Policy](#security-update-policy)
6. [Getting Support](#getting-support)
7. [Commercial Support Options](#commercial-support-options)

## Overview

Compliance Portal follows a **semantic versioning** scheme and provides different levels of support based on version age and stability.

### Support Commitment

We commit to:
- **Security patches** for all supported versions (critical issues within 24 hours)
- **Bug fixes** for active versions (non-critical issues within 14 days)
- **Feature updates** for current major version only
- **Upgrade assistance** when versions reach end-of-life

### What's Included in Support

| Category | Included |
|----------|----------|
| ✅ Installation & configuration help | Yes |
| ✅ Bug reports and fixes | Yes (for supported versions) |
| ✅ Documentation | Yes |
| ✅ Security vulnerability reporting | Yes |
| ✅ Performance optimization guidance | Yes |
| ❌ Custom feature development | No (unless commercial support) |
| ❌ Dedicated support engineer | No (unless commercial support) |
| ❌ SLA guarantees | No (unless commercial support) |

## Supported Versions

### Current Versions

| Version | Release Date | Support Status | Until Date | Security Until |
|---------|--------------|----------------|------------|----------------|
| **0.1.x** | 2024-04-27 | Beta | 2024-10-27 | 2024-12-31 |
| **1.0.x** | TBD | Active | TBD | TBD |
| **2.0.x** | TBD | Active | TBD | TBD |

### Status Definitions

| Status | Meaning | Updates | Commitment |
|--------|---------|---------|------------|
| **Current/Active** | Latest version in use | New features, bug fixes, security patches | Full support (see below) |
| **Maintenance** | Previous major version | Bug fixes, security patches only | 12 months from release of next major |
| **Security Only** | Older version | Security patches only | 6 months from entering security-only |
| **End of Life (EOL)** | No longer supported | No updates | Upgrade required for support |

### Beta Versions (0.x.x)

Early versions (0.x.x) are considered beta:
- **Breaking changes** may occur with minor version bumps (0.1.0 → 0.2.0)
- **Support duration**: 6 months from release
- **Upgrade path**: Must upgrade to gain new features
- **Not recommended** for production use

Once 1.0.0 is released, full semantic versioning (major.minor.patch) applies:
- **Major versions** (1.0, 2.0): 2 years of support per version
- **Minor versions** (1.1, 1.2): Supported until next major release + 6 months
- **Patch versions** (1.0.1, 1.0.2): Always supported by their major version

## Support Scope

### What We Support

We provide support for:

1. **Installation**
   - Helping you set up development environment (see **SETUP.md**)
   - Helping you deploy to production (see **INSTALLATION.md**)
   - Troubleshooting deployment issues

2. **Configuration**
   - Explaining environment variables (see **CONFIG.md**)
   - Helping you configure OIDC, database, Redis, etc.
   - Assisting with custom deployment topologies (Kubernetes, Docker, etc.)

3. **API & Features**
   - Explaining API endpoints (see **API.md**)
   - Helping you use portal features correctly
   - Troubleshooting feature issues

4. **Security & Compliance**
   - Reporting security vulnerabilities (see **SECURITY.md**)
   - Questions about security amendments (see **CISO-amendments-applied.md**)
   - Compliance questions (ISO 27001, SOC 2, GDPR)

5. **Performance**
   - Helping optimize query performance
   - Tuning configuration for your workload
   - Capacity planning

6. **Bug Fixes**
   - Investigating and fixing bugs
   - Backporting security patches to older versions
   - Providing workarounds for known issues

### What We Don't Support

We do not provide support for:

- **Custom code modifications** — If you modify the source code, you own the modifications
- **Unsupported versions** — EOL versions do not receive updates
- **Third-party integrations** — Unless documented in our official integration guides
- **Your operational infrastructure** — Database administration, Kubernetes, etc. (outside the portal's scope)
- **Custom feature development** — Unless you have commercial support

### Unsupported Platforms

We do not officially support:

- **Python < 3.12** — Portal requires Python 3.12+
- **Older databases** — PostgreSQL 10 or earlier
- **Exotic architectures** — ARM, 32-bit systems (we test on x86-64 and ARM64 only)
- **EOL operating systems** — Ubuntu 18.04 or earlier (we test on 20.04+)
- **Third-party packages not in requirements.txt** — Custom dependencies are unsupported

## Support Lifecycle

### Bug Fix Timeline

When you report a bug:

| Step | Timeline | Details |
|------|----------|---------|
| **Acknowledgment** | < 24 hours | We confirm receipt and assign to engineer |
| **Investigation** | < 72 hours | We reproduce and diagnose the issue |
| **Fix** | Depends on severity (see below) | Engineer develops and tests fix |
| **Release** | Depends on severity | Patch is released in next version |
| **Notification** | Upon release | You're notified of availability |

### Bug Fix Timeline by Severity

| Severity | Acknowledgment | Fix Target | Release |
|----------|----------------|-----------|---------|
| **Critical** (data loss, security) | 4 hours | 24 hours | Immediate (hotfix) |
| **High** (feature broken) | 8 hours | 7 days | Next patch |
| **Medium** (workaround exists) | 24 hours | 30 days | Next patch |
| **Low** (minor issue) | 48 hours | 90 days | Next minor release |

### Example Bug Fix Process

```
2024-04-27 15:00 UTC — Bug reported via GitHub Issues
  "Audit explorer search fails for vendors with special characters"
  
2024-04-27 16:30 UTC — Acknowledged by engineer
  "Confirmed. I can reproduce with vendor name containing &.
   Root cause: SQL injection prevention is over-sanitizing input.
   ETA for fix: 2024-05-02"

2024-04-29 10:00 UTC — Fix implemented
  "Fix ready for review. PR #456 escapes special characters properly
   while preserving search functionality. Tests added."

2024-04-29 14:00 UTC — Fix merged to main
  "Tests pass. Merging to main. Will be in 0.1.1-patch."

2024-05-01 09:00 UTC — Patch released
  "0.1.1 released with bug fix. Deployed to production.
   Notification sent to all users."

2024-05-02 09:00 UTC — Your notification
  You receive email: "Compliance Portal 0.1.1 released with bug fixes"
```

## Security Update Policy

Security updates are treated with highest priority and follow accelerated timelines.

### CVE Response Timeline

When a CVE (Common Vulnerabilities and Exposures) is published:

| Severity | CVSS Score | Response Time | Patch Timeline |
|----------|-----------|----------------|----------------|
| **Critical** | 9.0-10.0 | 4 hours | Within 24 hours |
| **High** | 7.0-8.9 | 8 hours | Within 7 days |
| **Medium** | 4.0-6.9 | 24 hours | Within 30 days |
| **Low** | 0.1-3.9 | 1 week | With next patch |

### Patch Availability

Security patches are released as:

1. **Hotfix** (Critical/High) — Immediate release outside normal release cycle
2. **Patch version** (Medium) — Released in next patch version (0.1.x → 0.1.x+1)
3. **Next release** (Low) — Included in next scheduled release

### Example Security Update

```
2024-04-27 09:00 UTC — CVE-2024-XXXXX published
  "Remote Code Execution in FastAPI via malformed header"
  CVSS: 9.1 (Critical)
  Affected versions: 0.115.0 - 0.115.3
  Fixed in: 0.115.4

2024-04-27 10:00 UTC — Compliance Portal assessed
  "We use FastAPI 0.115.4, which includes the fix.
   No action needed for current users.
   Notification: Security bulletin issued"

2024-04-27 16:00 UTC — Notification sent
  Subject: "Security Bulletin: FastAPI CVE-2024-XXXXX"
  "If you're using Compliance Portal 0.1.0 or later, you're protected.
   No action required. Keep your version up to date."
```

### End of Security Updates

When a version reaches end of life:

- **Last security update** is released as a patch
- **90-day notice** is given before support ends
- **Upgrade path** is provided to supported versions

### Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** create a public GitHub issue
2. **DO** email security@acme.io with details
3. **DO** include: description, steps to reproduce, impact
4. **DO** suggest a fix if you have one

See **SECURITY.md** for full vulnerability disclosure policy.

## When Support Ends

### End of Life (EOL) Dates

When a version reaches EOL:

1. **No further updates** are released
2. **You must upgrade** to get security patches
3. **Upgrade assistance** is provided (see "Upgrade Help" below)

### Pre-EOL Notifications

You'll receive notifications:

- **120 days before EOL**: "Version 0.1.x reaches EOL on [date]"
- **60 days before EOL**: "Version 0.1.x reaches EOL soon; plan your upgrade"
- **30 days before EOL**: "Version 0.1.x reaches EOL in [days]; upgrade now"
- **10 days after EOL**: "Version 0.1.x is no longer supported"

### Upgrade Assistance

To help you upgrade from EOL versions:

- **Migration guide** provided (how to upgrade without downtime)
- **Breaking changes** documented (if upgrading major versions)
- **Testing support** (help verify upgrade works)
- **Rollback plan** (if needed)

## Getting Support

### Free Support (Community)

Public support channels available to all users:

| Channel | Response Time | Best For |
|---------|---------------|----------|
| **GitHub Issues** | 24-72 hours | Bug reports, feature requests |
| **GitHub Discussions** | 24-72 hours | Questions, usage help |
| **Documentation** | Self-service | Setup, configuration, how-to |
| **Email: support@acme.io** | 24 hours | General inquiries |

**How to report an issue**:

1. Check **FAQ.md** for common questions
2. Check **SECURITY.md** for vulnerability disclosure
3. Create GitHub Issue with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Logs/error messages
   - Environment (OS, Python version, portal version)

### Commercial Support (Paid)

Enterprise customers can purchase support plans:

| Plan | Cost | SLA Response | SLA Resolution | Features |
|------|------|--------------|----------------|----------|
| **Starter** | $5K/year | 8 hours | 5 business days | Email support, 1 person |
| **Professional** | $15K/year | 4 hours | 2 business days | Email + phone, 3 people, advisory |
| **Enterprise** | Custom | 2 hours | 24 hours | Dedicated engineer, phone 24/7 |

**To purchase commercial support**: Contact sales@acme.io

### Internal Support (Organization)

If you're running Compliance Portal internally:

- **Slack channel** (#compliance-portal) — peer support
- **Weekly office hours** (Tuesdays 3 PM UTC) — live Q&A
- **Internal wiki** (internal.acme.io/compliance-portal) — organization-specific docs
- **On-call rotation** — 24/7 support for production issues

## Release & Support Timeline

### Example: Version 0.1.x Lifecycle

```
2024-04-27: Release 0.1.0 (initial release)
  - Status: Active
  - Support: 6 months

2024-05-15: Release 0.1.1 (patch release)
  - Fixes: Bug fixes, security patches
  - Backward compatible: Yes

2024-06-01: Release 0.2.0 (minor release)
  - New features: DSR enhancements, Qdrant integration
  - Breaking changes: None (semantic versioning)

2024-08-01: Release 1.0.0 (major release)
  - Status: 0.1.x becomes maintenance phase
  - 0.1.x support ends: 2025-08-01 (12 months from 1.0 release)
  - 0.1.x security ends: 2025-10-01 (14 months from 1.0 release)

2024-08-01: Release 0.1.5 (final patch for 0.1.x)
  - Receives security patches for 12-14 months

2025-08-01: 0.1.x EOL
  - No further updates
  - Users must upgrade to 1.0+
  - Upgrade assistance provided
```

## FAQ — Support Policy

**Q: I'm on version 0.1.2. Will I get security patches?**

A: Yes, until EOL on 2024-10-27. After that, upgrade to 1.0+ to continue receiving patches.

**Q: Can you backport a fix to version 0.1.0 even though it's old?**

A: If it's a critical security fix, yes. For non-security bugs, we recommend upgrading to latest version.

**Q: I have a critical issue in production. What do I do?**

A: 
1. Email security@acme.io with "CRITICAL" in subject
2. Page on-call engineer (in Opsgenie)
3. Provide full reproduction steps
4. Follow incident response procedures (see INCIDENT-RESPONSE.md)

**Q: How long until my bug gets fixed?**

A: Depends on severity (see Bug Fix Timeline above). Critical bugs: < 24 hours. High: 7 days. Medium: 30 days.

**Q: I'm not in a supported version. Can I still get help?**

A: We can provide limited guidance, but cannot commit to fixes for EOL versions. Upgrade to a supported version for full support.

**Q: Can I get support for my custom modified version?**

A: Limited. We can help with the core portal, but your modifications are your responsibility. Consider contributing changes upstream instead.

## Related Documents

- **SECURITY.md** — Security vulnerability reporting
- **FAQ.md** — Frequently asked questions
- **CHANGELOG.md** — Version history
- **INSTALLATION.md** — Deployment and upgrade procedures
