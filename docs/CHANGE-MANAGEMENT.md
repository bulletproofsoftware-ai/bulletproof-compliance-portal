# Change Management

This document describes the process for planning, testing, deploying, and verifying changes to the Compliance Portal in production environments.

## Table of Contents

1. [Overview](#overview)
2. [Change Classification](#change-classification)
3. [Change Request Process](#change-request-process)
4. [Testing & Verification](#testing--verification)
5. [Deployment Procedures](#deployment-procedures)
6. [Rollback Procedures](#rollback-procedures)
7. [Change Calendar](#change-calendar)

## Overview

Change Management ensures that all modifications to the Compliance Portal are:

- **Planned** — Not ad-hoc; scheduled in advance
- **Tested** — Verified to work in staging before production
- **Reviewed** — Approved by necessary stakeholders
- **Documented** — Tracked for audit compliance
- **Reversible** — Can be rolled back if issues occur

All changes follow this path:

```
Development → Testing → Staging → Production (with rollback plan)
```

### Change Types

| Type | Examples | Approval | Testing |
|------|----------|----------|---------|
| **Emergency patches** | Critical security fix, production outage | CISO + VP Eng | Fast-track (30 min) |
| **Regular patches** | Bug fix, minor enhancement | Release manager | Standard (1-2 days) |
| **Minor releases** | Feature addition, non-breaking | Release manager + tech lead | Standard (1-2 days) |
| **Major releases** | Breaking changes, architecture changes | CISO + VP Eng + Compliance | Extended (1+ week) |

## Change Classification

### By Impact

Each change is classified by its potential impact:

#### Low Impact
- Bug fixes with minimal scope
- UI/UX improvements
- Documentation updates
- Test infrastructure changes
- Dependency patches (non-security)

**Approval**: Release manager
**Testing**: Unit tests, smoke tests
**Deployment window**: Any (business hours preferred)
**Rollback**: Simple (revert commit)

#### Medium Impact
- New features with limited user reach
- Configuration changes
- Performance optimizations
- Database migrations on non-critical tables
- Security patches (non-critical)

**Approval**: Release manager + tech lead
**Testing**: Unit + integration tests, staging validation
**Deployment window**: Business hours (9 AM - 5 PM)
**Rollback**: Requires data migration rollback

#### High Impact
- New major features
- API changes
- Database schema changes
- Authentication/authorization changes
- Security amendments (CISO directives)
- Third-party integrations

**Approval**: Release manager + tech lead + CISO
**Testing**: Full test suite + load testing + staging soak test
**Deployment window**: Scheduled maintenance window
**Rollback**: Pre-defined rollback tested

#### Critical
- Emergency security patches
- Production outage fixes
- Compliance-critical changes
- Infrastructure changes

**Approval**: VP Engineering + CISO + CEO (for awareness)
**Testing**: Fast-track (30 min minimum)
**Deployment window**: Immediate (anytime, any day)
**Rollback**: In-flight rollback plan required

## Change Request Process

### Step 1: Create Change Request

**Timing**: Submit at least 5 business days before desired deployment (more for major changes)

**Template**:

```markdown
# Change Request: [Change Name]

## Summary
Brief 1-sentence description of the change.

## Details
- What is being changed?
- Why is this change needed?
- What problem does it solve?
- Who requested this change?

## Technical Details
- What components are affected?
- What dependencies does this require?
- Any database migrations? (describe)
- Any environment variable changes? (list)
- Any third-party service interactions? (list)

## Impact Assessment
- **Scope**: Which users are affected? (internal/public/both)
- **Risk level**: Low/Medium/High/Critical
- **Blast radius**: If this breaks, what stops working?
- **Estimated downtime**: 0 min (zero-downtime), < 5 min, 15-30 min, > 1 hour

## Testing Plan
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Staging deployment validated
- [ ] Load test passed (if performance-critical)
- [ ] Security scan passed (if security-related)
- [ ] Rollback plan tested

## Deployment Plan
- **Deployment method**: Rolling update, blue-green, feature flag, maintenance window
- **Deployment date/time**: [Date] [Time] UTC
- **Deployment duration**: [Estimated time]
- **Rollback plan**: [How to undo if issues occur]

## Approval
- [ ] Release manager approval
- [ ] Tech lead approval (if medium/high impact)
- [ ] CISO approval (if security-related)
- [ ] Compliance approval (if compliance-related)

## Sign-Off
- Requester: _______
- Date: _______
```

### Step 2: Technical Review

Engineering team reviews the change request:

- **Does the proposed change actually solve the problem?**
- **Are there any unintended side effects?**
- **Is the implementation approach sound?**
- **What are the risks?**
- **How confident are we in the testing?**
- **What could go wrong in production?**

**Approval**: Change request is approved or sent back for revision.

### Step 3: Risk Assessment

CISO and release manager assess risk:

- **Security impact**: Does this introduce new security risks?
- **Compliance impact**: Does this affect compliance controls?
- **Operational impact**: Do we have capacity to deploy and support?
- **Business impact**: What's the cost of deployment vs cost of not deploying?

**Decision**: Approve, conditional approval, or defer to safer time.

### Step 4: Scheduling

Release manager schedules the change:

- **Maintenance window**: If requires downtime, schedule in low-traffic period (typically weekdays 2-4 AM UTC)
- **Notification period**: Announce to affected users 24-48 hours in advance
- **Rollback window**: Ensure rollback can be executed within 30 min if needed

**Scheduled changes calendar**:
- Visible to all engineering staff
- Sent to status page subscribers
- Alerts on-call engineer

## Testing & Verification

### Pre-Deployment Testing

Before a change is deployed to production, it must pass:

#### 1. Unit Tests
```bash
# Run unit tests locally and in CI
pytest tests/unit/ -v

# Expected: 100% pass rate
# Coverage: >= 80% on modified code
```

#### 2. Integration Tests
```bash
# Test with external services (database, Redis, OIDC)
pytest tests/integration/ -v --tb=short

# Expected: 100% pass rate
# Services: PostgreSQL, Redis, OIDC mocked, Compliance service mocked
```

#### 3. Staging Deployment
```bash
# Deploy to staging environment
# (same config as production, but lower traffic)

# Run smoke tests
pytest tests/smoke/ -v

# Expected: All critical user paths work
# - Authentication succeeds
# - Audit search returns results
# - Evidence download works
# - PDF export succeeds
# - DSR submission works
```

#### 4. Security Scanning

For security-related changes:

```bash
# SAST (static analysis)
semgrep --config=p/owasp-top-ten .

# Dependency scanning
pip-audit
trivy scan .

# Expected: No critical/high vulnerabilities
```

#### 5. Performance Testing

For performance-critical changes:

```bash
# Load test in staging
ab -n 1000 -c 100 https://staging-portal.internal/audit/search

# Expected: p95 latency < 500ms, error rate < 1%
```

### Staging Soak Test

For high-impact changes, run the application in staging for 24-72 hours:

- Monitor error rate (should be 0%)
- Monitor latency (should be stable)
- Monitor memory usage (should not leak)
- Run business-as-usual user workloads

If any issues are discovered during soak test, the change is revised and re-tested.

## Deployment Procedures

### Zero-Downtime Deployment (Rolling Update)

Most changes use rolling updates, which require no downtime:

**Procedure**:

1. **Health check current version**:
```bash
curl https://portal.internal/healthz
# Expected: {"status":"ok","version":"0.1.5"}
```

2. **Update image in deployment**:
```bash
kubectl set image deployment/compliance-portal \
  portal=compliance-portal:v0.1.6 \
  --record
```

Kubernetes automatically:
- Creates new pod with v0.1.6
- Waits for it to become healthy
- Stops old pod
- Repeats for all replicas

3. **Monitor rollout**:
```bash
kubectl rollout status deployment/compliance-portal
# Should complete in 2-5 minutes
```

4. **Verify**:
```bash
# Test new version
curl https://portal.internal/healthz
# Expected: {"status":"ok","version":"0.1.6"}

# Check for errors
kubectl logs -f deployment/compliance-portal --tail=50
# Expected: No error messages

# Run smoke tests
pytest tests/smoke/ -v
# Expected: All pass
```

### Maintenance Window Deployment

For changes that require downtime (database schema changes, etc.):

1. **Announce maintenance window** (24 hours in advance)

2. **Disable public access** (optional, only if public portal affected):
```bash
# Route requests to maintenance page
kubectl patch ingress compliance-portal \
  -p '{"spec":{"defaultBackend":{"serviceName":"maintenance-page"}}}'
```

3. **Run pre-flight checks**:
```bash
# Backup database
pg_dump compliance_portal > backup-$(date +%s).sql

# Verify backups exist
ls -lh backup-*.sql
```

4. **Execute change** (with on-call engineer watching):
```bash
# Run database migration
psql -U portal -d compliance_portal -f migration-v0.1.6.sql

# Deploy new code
kubectl set image deployment/compliance-portal \
  portal=compliance-portal:v0.1.6

# Verify
curl https://portal.internal/healthz
```

5. **Restore public access**:
```bash
# Route traffic back to application
kubectl patch ingress compliance-portal \
  -p '{"spec":{"defaultBackend":{"serviceName":"compliance-portal-svc"}}}'
```

6. **Communicate**: Update status page with completion message

## Rollback Procedures

If a deployed change causes production issues, it can be rolled back:

### Quick Rollback (Zero-Downtime)

```bash
# Immediate rollback to previous version
kubectl rollout undo deployment/compliance-portal

# Verify
kubectl rollout status deployment/compliance-portal
curl https://portal.internal/healthz
# Expected: {"status":"ok","version":"0.1.5"}

# Verify no data loss (if applicable)
psql -c "SELECT COUNT(*) FROM audit_events WHERE created_at > NOW() - '30 min'::interval"
# Should show normal count
```

### Database Rollback

If a database migration caused issues:

```bash
# Restore from backup
psql -U portal -d compliance_portal < backup-20240427-143022.sql

# Verify data integrity
psql -c "SELECT COUNT(*) FROM audit_events"
psql -c "SELECT COUNT(*) FROM evidence"
# Counts should match pre-migration

# Rollback code
kubectl rollout undo deployment/compliance-portal

# Verify
curl https://portal.internal/healthz
# Expected: HTTP 200
```

### Partial Rollback

If only one feature is broken, other features can continue:

```bash
# Feature flag to disable broken feature
kubectl set env deployment/compliance-portal \
  FEATURE_PDF_EXPORT_ENABLED=false

# Leave other features running
# Users can continue using audit explorer, DSR, etc.

# Once issue is fixed, re-enable
kubectl set env deployment/compliance-portal \
  FEATURE_PDF_EXPORT_ENABLED=true
```

## Change Calendar

All planned changes are documented in the change calendar:

### This Month's Scheduled Changes

| Date | Time (UTC) | Change | Impact | Duration | Rollback |
|------|-----------|--------|--------|----------|----------|
| 2024-04-29 | 02:00 | Add database index on evidence table | 0 min downtime | 5 min | Instant |
| 2024-05-05 | 09:00 | Deploy v0.2.0 (DSR enhancements) | 50 users | 10 min | <5 min |
| 2024-05-12 | 03:00 | PostgreSQL major version upgrade | 30 min downtime | 45 min | 30 min |
| 2024-05-19 | 15:00 | Switch to new OIDC provider | 0 min downtime | 20 min | <5 min |

### Blackout Windows

No changes should be deployed during:

- **Holidays** (office closed)
- **Major events** (company all-hands, board meetings)
- **Known high-traffic periods** (end of quarter reporting)
- **Third-party maintenance windows** (OIDC provider, database)

Blackout dates:

```
2024-05-27 (Memorial Day)
2024-06-19 (Juneteenth)
2024-07-04 (Independence Day)
2024-11-28 (Thanksgiving)
2024-12-25 (Christmas)
2025-01-01 (New Year's Day)
```

## Emergency Change Process

For critical issues that cannot wait:

**Fast-track emergency change** (approval in 15 minutes):

1. Create change request marked **EMERGENCY**
2. Page VP Engineering and CISO immediately
3. Brief decision: approve or defer
4. If approved: deploy immediately with on-call engineer standing by
5. Post-deployment: detailed review within 24 hours

**Example emergency change**:
```
EMERGENCY: Critical security patch for CVE-2024-XXXXX in FastAPI

Impact: Allows remote code execution in production
Status: CVE published 2 hours ago
Action: Deploy v0.1.7-hotfix immediately
Approval: VP Eng approved 14:32 UTC
Deployment: 14:45 UTC (in progress)
Rollback: Ready if needed
```

## Change Audit Trail

All changes are recorded for compliance audits:

```bash
# View all deployments
kubectl rollout history deployment/compliance-portal

deployment.apps/compliance-portal
REVISION  CHANGE-CAUSE
5         Bugfix for audit explorer slowness
4         Deploy v0.1.5 (feature additions)
3         Emergency patch for CVE-2024-XXXX
2         Deploy v0.1.4 (initial release)
1         Initial deployment
```

## Related Documents

- **INSTALLATION.md**: Production deployment procedures
- **INCIDENT-RESPONSE.md**: How to handle incidents caused by changes
- **CHANGELOG.md**: Version history and release notes
- **SECURITY.md**: Security-specific change procedures
