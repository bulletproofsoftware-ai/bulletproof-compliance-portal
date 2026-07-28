# How to Report a Defect (Bug)

This guide explains how to report bugs and issues you find in Compliance Portal. Your bug reports help us improve the product for everyone.

## When to Report a Bug

Report a bug if:

- A feature doesn't work as expected
- You get an unexpected error message
- The application crashes or becomes unresponsive
- Documentation is incorrect or unclear
- Performance is unusually slow
- Security vulnerability discovered

**Note**: For security vulnerabilities, see [Security Reporting](../../SECURITY.md) instead of using the public bug tracker.

## Before You Report

### Check If It's Already Reported

1. **Search GitHub Issues**: https://github.com/[org]/compliance-portal/issues
   - Use keywords from the problem
   - Filter by `type:bug` label
   - Check closed issues (may be fixed in a later version)

2. **Check Troubleshooting Guide**: See the project documentation in [`docs/`](../../docs/)
   - Your issue may have a known workaround
   - Common issues are documented with solutions

3. **Check Release Notes**: See [Changelog](../../CHANGELOG.md)
   - Recent releases may have fixed your issue
   - Upgrade to the latest version to confirm

### Gather Information

Before reporting, collect this information:

- **Version**: What version are you using? (Run `compliance-portal --version`)
- **Environment**: OS (Linux/macOS/Windows), Python version, deployment method (Docker/manual)
- **Steps to Reproduce**: Exact steps that trigger the bug
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Error Messages**: Full error text or screenshot
- **Screenshots**: Visual evidence of the issue
- **Logs**: Relevant log output with timestamps

## How to Report

### Method 1: GitHub Issues (Preferred)

1. **Go to**: https://github.com/[org]/compliance-portal/issues/new/choose
2. **Select**: "Bug Report" template
3. **Fill in all sections** of the template:
   ```markdown
   **Environment**
   - Version: 0.1.0
   - OS: Ubuntu 22.04
   - Python: 3.11
   - Deployment: Docker

   **Description**
   Clear description of the bug.

   **Steps to Reproduce**
   1. Click "Create Audit"
   2. Fill in the form with [specific data]
   3. Click "Save"
   4. See error

   **Expected Behavior**
   Audit should be created and I should see success message.

   **Actual Behavior**
   Application shows error: "500 Internal Server Error"

   **Error Messages**
   ```
   Traceback (most recent call last):
     File "portal/routers/audit.py", line 123, in create_audit
       result = db.execute(INSERT_QUERY)
   sqlite3.OperationalError: database is locked
   ```

   **Screenshots**
   [Attach screenshot showing the error]

   **Additional Context**
   Happens every time with audit entries > 1MB.
   ```
4. **Click "Submit new issue"**

### Method 2: Email (Alternative)

If you prefer not to use GitHub:

**Email**: support@example.com

**Subject Line**: `[BUG] Brief description of the problem`

**Body**: Include all the information from the GitHub issue template above.

## Bug Report Best Practices

### Be Specific

❌ **Poor**: "Search doesn't work"

✓ **Good**: "Full-text search on the 'Findings' page returns zero results when searching for 'data breach' even though matching entries exist in the system"

### Provide Exact Steps

❌ **Poor**: "I was using the app and got an error"

✓ **Good**:
1. Log in as auditor@example.com
2. Navigate to Audit → Entries
3. Click filter icon
4. Type "2024-04" in date range field
5. Click "Apply"
6. See error: "Invalid date format"

### Include Error Messages

❌ **Poor**: "Something went wrong"

✓ **Good**:
```
Error: TypeError: 'NoneType' object is not subscriptable
File: portal/services/evidence.py, line 45, in extract_metadata
  author = record['metadata']['author']
```

### One Bug Per Report

❌ **Poor**: "Bugs found: Login doesn't work, search is slow, PDF doesn't download, etc."

✓ **Good**: One separate issue for each problem

## What Happens After You Report

### 1. Triage (24-48 hours)

Our team will:
- Confirm the bug is reproducible
- Assign severity level
- Assign to appropriate team member
- Ask for clarification if needed

### 2. Investigation (varies by severity)

| Severity | Investigation Timeline | Example |
|----------|------------------------|---------|
| **Critical** | < 24 hours | Application completely broken, data loss |
| **High** | < 7 days | Important feature broken, workaround possible |
| **Medium** | < 30 days | Feature partially broken, workaround available |
| **Low** | < 90 days | Minor issue, no workaround needed |

### 3. Resolution

Once the bug is fixed:
- Fix is released in next patch version
- Your issue is marked as "fixed"
- Release notes mention the fix
- Notification sent (if you subscribed)

### 4. Follow-Up

After a fix is released:
- We appreciate if you test the fix and confirm it works
- Provide feedback: "Verified fixed in v0.1.1"
- Report if the fix didn't work as expected

## Severity Levels

We use these severity levels to prioritize fixes:

| Severity | Impact | Response Time | Examples |
|----------|--------|---------------|----|
| **Critical** | Complete outage, data loss, security risk | < 24h | Application won't start, all data deleted, auth bypass |
| **High** | Important feature broken, significant impact | < 7 days | Login doesn't work, audit trail corrupted, PDF export fails |
| **Medium** | Feature partially broken, workaround exists | < 30 days | Search is slow, export takes 5 minutes, UI glitch |
| **Low** | Minor issue, no practical impact | < 90 days | Typo in label, tooltip unclear, minor layout issue |

## Security Vulnerabilities (Different Process)

**DO NOT report security vulnerabilities in public GitHub issues.**

For security issues, see [Security Reporting](../../SECURITY.md) to report privately.

## Expected Response Times

| Status | Response Time | What It Means |
|--------|---------------|--------------|
| **New** | Acknowledged within 24h | We received and read your report |
| **Triaged** | Within 48h | We confirmed/reproduced the bug |
| **Assigned** | Within 1 week | Developer is investigating |
| **In Progress** | Varies | Developer is working on a fix |
| **Ready for Test** | Varies | Fix is ready for you to test |
| **Fixed** | Varies | Fix released in next version |
| **Won't Fix** | Within 1 month | Explanation of why we're not fixing this |

## Frequently Asked Questions

### "Can I get a faster response if I have a paid plan?"

Yes! Customers with commercial support plans get priority response:
- **Premium**: 4-hour response time
- **Enterprise**: 1-hour response time

See the maintainer at marc@bulletproofsoftware.ai for details.

### "Will you fix my bug immediately?"

Critical bugs (security, complete outage) get immediate attention. Other bugs are fixed in priority order with other requests. If urgent, consider purchasing premium support.

### "What if I'm not sure if it's a bug or just how the software works?"

If you're unsure, report it anyway! Write "Not sure if this is a bug" and describe what confuses you. We'll help clarify.

### "Can I see the status of my bug report?"

Yes! Stay updated on your GitHub issue:
- **Watch** the issue to get notifications
- Check the issue periodically for updates
- See "Linked PR" when a fix is in progress
- See version tag when the fix is released

### "Can I contribute a fix myself?"

Absolutely! We love community contributions:
1. Fork the repository
2. Create a branch for your fix
3. Submit a pull request with description of the fix
4. We'll review and merge if it meets our standards

See [Contributing](../../CONTRIBUTING.md) for detailed guidelines.

### "Why was my bug report closed without being fixed?"

Possible reasons:
1. **Duplicate**: Same bug already reported
2. **Not reproducible**: We couldn't recreate the issue (ask for more details)
3. **Working as designed**: The behavior is intentional
4. **Out of scope**: Not part of this project
5. **No activity**: Old issues with no response for 90 days

If you disagree, comment on the issue and we'll reconsider.

## Tools to Help You Report Better

### Collect Logs

If the application crashed, logs contain critical information:

```bash
# Find logs (location depends on installation method)
# Docker:
docker logs [container-name]

# Manual installation:
tail -f /var/log/compliance-portal.log

# Include last 50 lines of log in your bug report
tail -50 /var/log/compliance-portal.log > logs.txt
```

### Take Screenshots

- **macOS**: Cmd + Shift + 4
- **Linux**: PrtScn or use Gnome Screenshot
- **Windows**: Win + Shift + S

Attach the screenshot to your GitHub issue.

### Record a Video (For Complex Issues)

For complex bugs, a short video showing the steps can be very helpful:

- **macOS**: QuickTime Player → File → New Screen Recording
- **Linux**: Gnome Shell Recorder (Ctrl + Alt + Shift + R)
- **Windows**: Xbox App → Win + G

Upload to YouTube unlisted and link in your issue.

## Related Resources

- **Troubleshooting Guide**: the project documentation in [`docs/`](../../docs/)
- **Security Reporting**: [Report Security Issues](../../SECURITY.md)
- **Support Options**: marc@bulletproofsoftware.ai
- **Contributing**: [Contributing Guidelines](../../CONTRIBUTING.md)

---

**Need Help?**
- **Chat with us**: GitHub Discussions
- **Email us**: support@example.com
- **View Status**: https://status.example.com

**Thank you for helping us build better software!**
