# Incident Response & Operations Runbook

This document provides procedures for responding to incidents affecting the Compliance Portal in production.

## Table of Contents

1. [Incident Severity Levels](#incident-severity-levels)
2. [On-Call Rotation](#on-call-rotation)
3. [Incident Response Process](#incident-response-process)
4. [Common Issues & Fixes](#common-issues--fixes)
5. [Communication & Escalation](#communication--escalation)
6. [Post-Incident Review](#post-incident-review)

## Incident Severity Levels

Incidents are classified by impact and urgency:

| Level | Description | Impact | Response Time | Fix Target | Examples |
|-------|-------------|--------|----------------|------------|----------|
| **SEV1** | Critical outage | Complete service down | **15 min** | **2 hours** | Compliance service unreachable, database offline, all routes failing |
| **SEV2** | Major degradation | Feature unavailable | **30 min** | **8 hours** | PDF export broken, audit explorer slow, OIDC provider unavailable |
| **SEV3** | Minor issue | Performance impact | **4 hours** | **24 hours** | Latency > 1 sec, minor route failing, non-critical endpoint down |
| **SEV4** | Low impact | Cosmetic/UX issue | **1 day** | **1 week** | Typo in UI, button styling, non-critical feature misbehaving |

### Determining Severity

Use this flowchart to classify incidents:

```
┌─ Can users authenticate? ────NO──→ SEV1
│  ├─ YES
│
├─ Can users access core features? ────NO──→ SEV2
│  ├─ YES
│
├─ Is performance acceptable (< 500ms)? ────NO──→ SEV3
│  ├─ YES
│
└─ Is it a cosmetic issue? ────YES──→ SEV4
   └─ NO ────→ SEV3
```

## On-Call Rotation

### Primary On-Call

The primary on-call engineer is available 24/7 for SEV1/SEV2 incidents.

| Week | Engineer | Contact | Backup |
|------|----------|---------|--------|
| 2024-04-29 | John Doe | john@acme.io, +1-555-0123 | Jane Smith |
| 2024-05-06 | Jane Smith | jane@acme.io, +1-555-0124 | Bob Johnson |
| 2024-05-13 | Bob Johnson | bob@acme.io, +1-555-0125 | Alice Lee |

Rotation repeats every 3 weeks. Schedule is published in:
- Slack channel: #incident-on-call
- Opsgenie: https://opsgenie.acme.io/schedule/compliance-portal
- Email: on-call@acme.io

### Escalation Contacts

If the primary on-call does not respond within 10 minutes:

1. **Escalation 1** (10 min): Backup engineer
2. **Escalation 2** (20 min): Engineering lead
3. **Escalation 3** (30 min): CISO / Director of Engineering

## Incident Response Process

### Step 1: Detection & Triage (First 15 minutes)

An incident is detected via:

- **Monitoring alerts** (Prometheus/Grafana, Datadog, Wazuh)
- **Customer reports** (email, support, direct contact)
- **Internal discovery** (engineer notices an issue)

**Actions**:

```bash
# 1. Acknowledge the alert in Opsgenie/PagerDuty
opsgenie incident acknowledge <incident-id>

# 2. Determine severity level (use flowchart above)
# SEV1 = Critical, SEV2 = Major, SEV3 = Minor, SEV4 = Low

# 3. Create incident channel in Slack
/incident-declare-sev1 "Portal database offline — users cannot authenticate"

# This automatically:
# - Creates #incident-2024-04-27-portal-db Slack channel
# - Invites on-call engineer, CISO, relevant team leads
# - Starts incident timer
# - Sends notifications to stakeholders

# 4. Post initial summary in incident channel
"SEV1: Database offline since 14:23 UTC
Impact: Users cannot log in, all features unavailable
Suspected cause: PostgreSQL connection timeout
Action: Investigating database cluster status"

# 5. Page additional responders if needed
/incident-page-sev1 security  # For security incidents
/incident-page-sev1 database  # For database issues
```

### Step 2: Investigation (Ongoing)

While the incident is ongoing, gather information:

```bash
# Check portal logs
kubectl logs -f deployment/compliance-portal --tail=200 | grep -i error

# Check metrics
# Dashboard: https://grafana.acme.io/d/compliance-portal
# - CPU usage
# - Memory usage
# - Request rate
# - Error rate
# - Database connections

# Test critical endpoints
curl -v https://portal.internal/healthz
# Expected: 200 OK {"status":"ok","version":"0.1.0"}

curl -v https://portal.internal/audit/search?q=test \
  -H "Authorization: Bearer $TEST_TOKEN"
# Expected: 200 OK with results

# Check dependent services
nslookup compliance-svc.internal
# Expected: resolves to IP

psql postgresql://portal:$DB_PASSWORD@postgres.internal:5432/compliance_portal \
  -c "SELECT 1"
# Expected: 1 (connection works)

redis-cli -h redis.internal ping
# Expected: PONG

# Check logs of dependent services
kubectl logs -f deployment/compliance-service --tail=100
kubectl logs -f deployment/postgres-operator --tail=100
```

**Post findings in incident channel** as you discover them:

```
"Investigation findings:
- Portal logs: Connection refused to postgres.internal:5432
- Metrics: PostgreSQL connection pool exhausted (10/10 connections used)
- Health check: /healthz returns 500 Database connection failed
- Dependent services: compliance-svc is healthy, redis is healthy
- Root cause: Database is accepting connections but responding slowly,
  causing connection pool to fill up
- Next: Contact database team to investigate slow queries"
```

### Step 3: Mitigation & Fix

Once you've identified the cause, take action:

#### Common Mitigations

**Memory/CPU exhaustion**:

```bash
# Increase pod resources (temporary)
kubectl set resources deployment/compliance-portal \
  --limits=cpu=2000m,memory=2Gi \
  --requests=cpu=1000m,memory=1Gi

# If that doesn't help, restart the deployment
kubectl rollout restart deployment/compliance-portal
```

**Database connection pool exhausted**:

```bash
# Increase pool size
kubectl set env deployment/compliance-portal \
  DB_POOL_SIZE=20  # Increase from default 10

# Restart to pick up new env var
kubectl rollout restart deployment/compliance-portal

# Or immediately scale down other services that use the database
kubectl scale deployment/background-worker --replicas=0
```

**OIDC provider unavailable**:

```bash
# Check if OIDC provider is actually down
curl -i https://auth.example.com/.well-known/openid-configuration

# If down, update routing to skip OIDC
# (This is a temporary workaround; proper fix requires OIDC to come back online)
kubectl patch configmap compliance-portal-config \
  -p '{"data": {"OIDC_DISCOVERY": "false"}}'
```

**Compliance service unreachable**:

```bash
# Check if service is reachable
curl -k https://compliance-svc.internal/health \
  --cert /etc/ssl/certs/client.crt \
  --key /etc/ssl/certs/client.key

# If down, the portal will gracefully degrade
# But check mTLS certificate validity
openssl x509 -in /etc/ssl/certs/client.crt -noout -dates
# If expired, update certificates:
kubectl create secret tls compliance-client-tls \
  --cert=new-client.crt --key=new-client.key \
  -o yaml | kubectl apply -f -
```

#### Escalation Path

If you cannot fix the issue:

1. **Escalate to team lead** (if SEV1 and >30 min unfixed)
2. **Escalate to CISO** (if security-related or compliance impact)
3. **Escalate to VP Engineering** (if widespread outage or multiple systems)
4. **Engage vendors** (if third-party service is down: OIDC provider, AWS support, etc.)

### Step 4: Verification (Restore & Confirm)

Once you believe the issue is fixed:

```bash
# 1. Test critical user flows
# a) Authentication
curl -X POST https://portal.internal/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass"
# Expected: Redirect to OIDC provider (303 status)

# b) Audit search (authenticated)
curl https://portal.internal/audit/search?q=vendor=acme \
  -H "Authorization: Bearer $TEST_TOKEN"
# Expected: 200 OK with results

# c) PDF export (authenticated)
curl https://portal.internal/audit/evidence/e123/export \
  -H "Authorization: Bearer $TEST_TOKEN" > evidence.pdf
# Expected: PDF file downloaded successfully

# d) DSR submission (public)
curl -X POST https://portal.dsr/submit \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","request_type":"data_access"}' \
  -F "g-recaptcha-response=$CAPTCHA_TOKEN"
# Expected: 200 OK with confirmation

# 2. Monitor metrics for 5-10 minutes
# Verify that error rate drops to normal (< 0.1%)
# Verify that latency returns to baseline (< 100ms p95)

# 3. Run smoke test suite
pytest tests/smoke_tests.py -v
# Expected: All tests pass (health, auth, audit, export, DSR)

# 4. Update incident channel
"✅ FIXED
- Issue: Database connection pool exhausted due to slow queries
- Fix: Identified long-running query (analytics batch job) and killed it
- Verification: All critical user flows passing, metrics normal
- Status: Monitoring for 30 minutes to ensure stability
- Next: Root cause analysis (slow query on evidence table)"
```

### Step 5: Communication (Ongoing)

Update stakeholders every 15-30 minutes during the incident:

**Status page update** (public):

```
[15:00 UTC] Investigating — Some users may experience degraded performance
[15:15 UTC] Impact identified — Database performance is slow; team is working on fix
[15:30 UTC] Partial restoration — Service partially restored; some features still slow
[16:00 UTC] Resolved — All features restored; monitoring for stability
[17:00 UTC] Post-incident — Investigation complete; improvements planned
```

**Incident channel updates** (internal):

```
15:00 - SEV1 declared: Database offline
15:05 - Database team engaged; slow queries identified
15:15 - Long-running analytics job killed; database responding faster
15:20 - Portal container restarted; users can now authenticate
15:25 - All critical features verified; incident resolved
15:30 - Will monitor for 1 hour; root cause analysis to follow
```

**Emails/SMS to executives** (for SEV1 only):

```
Subject: Incident Report — Compliance Portal
From: on-call@acme.io
To: ciso@acme.io, vp-engineering@acme.io, ceo@acme.io

INCIDENT SUMMARY
Incident: Compliance Portal service degradation
Severity: SEV1 (critical — all users affected)
Duration: 15 minutes (14:00-14:15 UTC)
Resolved: Yes ✅
Status Page: https://status.acme.io

ROOT CAUSE
Long-running analytics batch job on PostgreSQL exhausted connection pool,
preventing new requests from being processed.

IMPACT
- 100% of users unable to authenticate during 14:00-14:15 UTC
- 50% of audit events not recorded (partial recovery)
- 0 data breaches or security incidents

RESOLUTION
Stopped the batch job, restarted connection pool, verified all services.

NEXT STEPS
- Schedule post-mortem review (2024-04-27 @17:00 UTC)
- Implement connection pool monitoring alerts
- Optimize slow queries on evidence table
- Add circuit breaker to prevent batch job from blocking prod
```

## Common Issues & Fixes

### Issue: "Connection refused" to Database

**Symptoms**:
- Logs: `psycopg.OperationalError: connection refused`
- Health check: Fails
- Error rate: 100%

**Diagnosis**:

```bash
# 1. Check if database pod is running
kubectl get pods -l app=postgres
# If no pods running or CrashLoopBackOff, database is down

# 2. Check database logs
kubectl logs deployment/postgres -c postgres --tail=50 | grep -i error

# 3. Test connectivity
kubectl exec -it deployment/compliance-portal -- \
  psql postgresql://portal:$DB_PASSWORD@postgres:5432/compliance_portal \
  -c "SELECT 1"
```

**Fixes**:

| Symptom | Fix |
|---------|-----|
| Pod is in CrashLoopBackOff | `kubectl logs` to see startup error; may need to resize PVC if disk full |
| Pod is running but not responding | Restart database: `kubectl rollout restart deployment/postgres` |
| Connection pool exhausted | Increase pool size: `kubectl set env deployment/compliance-portal DB_POOL_SIZE=20` |
| Slow database responses | Check long-running queries (see below) |

**Check for slow queries**:

```bash
# Connect to database
psql postgresql://portal:$DB_PASSWORD@postgres:5432/compliance_portal

# Show current slow queries
SELECT query, duration FROM pg_stat_statements
  WHERE duration > 1000  -- queries taking > 1 second
  ORDER BY duration DESC;

# Kill a long-running query (CAREFULLY)
SELECT pid, query, duration FROM pg_stat_activity
  WHERE state = 'active' AND duration > 60000;  -- > 1 minute
SELECT pg_terminate_backend(pid);  -- Replace pid with actual value
```

### Issue: "OIDC provider unreachable"

**Symptoms**:
- Logs: `httpx.ConnectError: Failed to connect to auth.example.com`
- Health check: Passes (portal is up)
- Error rate: 100% for authenticated routes

**Diagnosis**:

```bash
# 1. Check if OIDC provider is reachable
curl -i https://auth.example.com/.well-known/openid-configuration

# 2. Check portal logs for OIDC errors
kubectl logs deployment/compliance-portal -c portal --tail=100 | grep -i oidc

# 3. Check DNS resolution
nslookup auth.example.com
# If DNS fails, contact network team
```

**Fixes**:

| Root Cause | Fix |
|------------|-----|
| OIDC provider is actually down | Contact OIDC provider support; consider failover provider if available |
| Network connectivity broken | Contact network team; check firewalls, proxies, DNS |
| Certificate validation failing | Update CA bundle: `kubectl set env deployment/compliance-portal OIDC_CA_BUNDLE=...` |
| Token endpoint changed | Manually update OIDC config (temporary): `kubectl set env deployment/compliance-portal OIDC_TOKEN_ENDPOINT=...` |

### Issue: "Redis connection failed"

**Symptoms**:
- Logs: `redis.ConnectionError: Error 113 connecting to redis.internal:6379`
- Health check: Passes
- Error rate: 0% but sessions are lost after pod restart

**Diagnosis**:

```bash
# 1. Check if Redis pod is running
kubectl get pods -l app=redis

# 2. Test Redis connectivity
kubectl exec -it deployment/compliance-portal -- redis-cli -h redis ping

# 3. Check Redis logs
kubectl logs deployment/redis --tail=50 | grep -i error
```

**Fixes**:

| Root Cause | Fix |
|------------|-----|
| Redis pod crashed | `kubectl rollout restart deployment/redis` |
| Redis is running but full | Clear old sessions: `redis-cli FLUSHDB` (⚠️ logs out all users) |
| Network connectivity broken | Check firewall rules and network policies |
| Redis password changed | Update REDIS_URL env var with new password |

**Note**: If Redis is unavailable, the portal will fall back to in-memory sessions, which are lost on pod restart. Users will be logged out. This is acceptable for a few hours but not for days.

### Issue: "Compliance service timeout"

**Symptoms**:
- Logs: `httpx.TimeoutException: Request timed out after 10.0s`
- Audit explorer is slow or returns no results
- Gate decision workspace cannot load data

**Diagnosis**:

```bash
# 1. Test compliance service directly
curl -k https://compliance-svc.internal/health \
  --cert /etc/ssl/certs/client.crt \
  --key /etc/ssl/certs/client.key \
  -v

# 2. Measure response time
time curl -k https://compliance-svc.internal/api/v1/compliance/audit \
  --cert /etc/ssl/certs/client.crt \
  --key /etc/ssl/certs/client.key

# 3. Check compliance service logs
kubectl logs deployment/compliance-service --tail=100 | grep -i slow
```

**Fixes**:

| Root Cause | Fix |
|------------|-----|
| Compliance service is slow | Contact compliance service team; it may be under heavy load |
| Network latency is high | Check network metrics; may need to route through different network path |
| Portal timeout is too low | Increase timeout: `kubectl set env deployment/compliance-portal COMPLIANCE_API_TIMEOUT_S=30` |
| mTLS certificate is invalid | Renew certificate: `kubectl create secret tls compliance-client-tls --cert=new.crt --key=new.key -o yaml \| kubectl apply -f -` |

### Issue: "PDF export fails"

**Symptoms**:
- Logs: `weasyprint.exceptions.InvalidURL` or `SSRF blocked`
- Export button hangs or returns 500 error
- Watermark does not appear

**Diagnosis**:

```bash
# 1. Check PDF export logs
kubectl logs deployment/compliance-portal -c portal --tail=100 | grep -i "pdf\|weasyprint"

# 2. Test PDF generation locally
curl https://portal.internal/audit/evidence/e123/export \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/pdf" \
  -v
```

**Fixes**:

| Symptom | Fix |
|---------|-----|
| "SSRF blocked" error | Check if URL is private IP; PDF gen is SSRF-protected intentionally |
| "Cairo not found" error | Ensure system dependencies installed: `apt-get install libcairo2-dev` |
| Watermark not appearing | Check if watermark template is rendered: `kubectl logs...` for template errors |
| Memory error (OOM) | PDF generation can be memory-intensive; increase pod memory limit |
| Timeout | Large PDFs take time; increase timeout: `kubectl set env ... PDF_GENERATION_TIMEOUT_S=60` |

## Post-Incident Review

After every SEV1 or SEV2 incident, conduct a post-incident review (PIR) within 48 hours.

### PIR Template

**Meeting**: 2024-04-27 @ 17:00 UTC
**Attendees**: On-call engineer, CISO, database team lead, engineering lead
**Duration**: 1 hour

#### 1. Incident Timeline

```
14:00 UTC - Incident started: Portal returned 500 errors
14:05 UTC - On-call engineer paged
14:10 UTC - Root cause identified: Database connection pool exhausted
14:15 UTC - Slow query killed; portal recovered
14:30 UTC - All services verified healthy
16:00 UTC - Incident declared resolved
```

#### 2. Root Cause Analysis

```
PRIMARY CAUSE:
Long-running analytics batch job (scheduled at 14:00 UTC daily) executed
a query that scanned the entire evidence table without using an index.
The query held a connection for 15+ minutes, exhausting the pool.

CONTRIBUTING FACTORS:
1. No query timeout enforced for batch jobs
2. No monitoring alert for slow queries
3. No circuit breaker to prevent batch job from blocking production
4. Evidence table index missing on (vendor_id, created_at) columns
```

#### 3. Impact Assessment

```
DURATION: 15 minutes
USERS AFFECTED: 100% (550 users)
FEATURES AFFECTED: All authenticated routes (audit, evidence, DSR, reports)
DATA LOSS: 50 audit events not recorded during outage
FINANCIAL IMPACT: ~$5K (50 minutes of compliance operations disrupted)
REPUTATION IMPACT: Medium (external auditor was testing during incident)
```

#### 4. Action Items

| Action | Owner | Due Date | Priority |
|--------|-------|----------|----------|
| Add database query timeout (5 sec for batch jobs) | Database team | 2024-04-28 | P1 |
| Create Prometheus alert for slow queries (> 1 sec) | SRE | 2024-04-28 | P1 |
| Add index on evidence table (vendor_id, created_at) | Database team | 2024-04-29 | P1 |
| Implement circuit breaker for batch jobs | Engineering | 2024-05-04 | P2 |
| Run batch jobs in separate account with lower pool size | Engineering | 2024-05-04 | P2 |
| Add load test for concurrent batch + production | QA | 2024-05-11 | P3 |

#### 5. Lessons Learned

```
WHAT WENT WELL:
+ On-call engineer responded within 5 minutes
+ Root cause identified quickly using logs and metrics
+ Status page kept up to date during incident

WHAT COULD BE BETTER:
- No proactive alert for slow queries (only noticed when pool exhausted)
- Batch job and production share same database connection pool
- No circuit breaker to prevent batch job from affecting prod users
- Documentation didn't mention database timeouts

SYSTEMIC IMPROVEMENTS:
- Implement query monitoring and alerting
- Separate batch jobs to different database pool
- Add circuit breaker pattern for external dependencies
- Update runbook with batch job troubleshooting
```

### Follow-up Actions

After the PIR:

1. **Create tickets**: Each action item becomes a GitHub issue
2. **Priority mapping**: P1 = fix within 1 week, P2 = fix within 1 month, P3 = plan for next quarter
3. **Communicate**: Send PIR summary to leadership (non-technical summary)
4. **Update runbook**: Add new procedures discovered during incident
5. **Schedule follow-up**: 2 weeks later, verify all P1 items completed

### Prevention Measures

Long-term prevention:

```bash
# 1. Implement query timeout
# In PostgreSQL config:
statement_timeout = 5000  # 5 seconds for batch jobs

# 2. Create alert for slow queries
# Prometheus rule:
- alert: SlowDatabaseQueries
  expr: pg_stat_statements_duration > 1000
  for: 2m
  annotations:
    summary: "Slow query detected ({{ $value }}ms)"

# 3. Add database index
CREATE INDEX idx_evidence_vendor_created ON evidence(vendor_id, created_at);

# 4. Separate connection pools
# In application config:
batch_jobs_pool_size = 3  # Max 3 concurrent batch jobs
production_pool_size = 10  # Max 10 concurrent prod requests
```
