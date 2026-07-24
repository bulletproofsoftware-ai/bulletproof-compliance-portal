# Compliance Mapping & Evidence Documentation

This document maps Compliance Portal's technical controls to major compliance frameworks and provides evidence of compliance implementation.

> Created per CISO Architecture Review AMD-20 (compliance evidence collection & audit trail).

## Table of Contents

1. [Overview](#overview)
2. [Compliance Frameworks](#compliance-frameworks)
3. [Control Mapping](#control-mapping)
4. [Evidence Collection](#evidence-collection)
5. [Audit Artifacts](#audit-artifacts)
6. [Certification Status](#certification-status)

## Overview

The Compliance Portal is designed to support organizations in achieving and maintaining compliance with multiple regulatory and industry frameworks. The application itself implements security and compliance controls aligned with:

- **SOC 2 Type II**: Trust Service Criteria (security, availability, processing integrity, confidentiality, privacy)
- **ISO 27001:2022**: Information Security Management System
- **GDPR**: General Data Protection Regulation (EU data privacy)
- **HIPAA**: Health Insurance Portability and Accountability Act (US healthcare)
- **PCI DSS**: Payment Card Industry Data Security Standard
- **NIST SP 800-218**: Secure Software Development Framework (SSDF)

This document provides a mapping of implemented controls and evidence for each framework.

## Compliance Frameworks

### SOC 2 Type II (Trust Services Criteria)

SOC 2 Type II evaluates controls related to **security, availability, processing integrity, confidentiality, and privacy** over a period of time (typically 6-12 months).

**Applicable To**: Service organizations handling customer data

**Key Control Domains**:
1. **CC (Common Criteria)**: System and organization controls
2. **A (Availability)**: Controls preventing unauthorized denial of service
3. **C (Confidentiality)**: Controls preventing unauthorized disclosure
4. **P (Processing Integrity)**: Controls preventing unauthorized processing
5. **PI (Privacy)**: Controls over personal information collection, use, retention

### ISO 27001:2022 (ISMS)

ISO 27001 is an international standard for information security management systems with 93 detailed controls across 14 domains.

**Applicable To**: All organizations seeking to implement formal ISMS

**Key Control Domains**:
- A.5 Organizational Controls
- A.6 People Controls
- A.7 Physical & Environmental Controls
- A.8 Technological Controls (cryptography, access control, detection, recovery)
- A.9 Operational Controls

### GDPR (General Data Protection Regulation)

GDPR requires organizations handling EU resident data to demonstrate compliance with data protection principles and individual rights.

**Applicable To**: Any organization processing EU resident personal data

**Key Articles**:
- Art. 5: Data protection principles (lawfulness, fairness, transparency, etc.)
- Art. 25-32: Data subject rights and technical safeguards
- Art. 33-36: Breach notification and privacy impact assessment

### HIPAA (Health Insurance Portability and Accountability Act)

HIPAA requires covered entities and business associates handling Protected Health Information (PHI) to implement administrative, physical, and technical safeguards.

**Applicable To**: Healthcare organizations and their business associates

**Key Rule Components**:
- **Privacy Rule**: How PHI can be used and disclosed
- **Security Rule**: Technical, administrative, and physical safeguards for ePHI
- **Breach Notification Rule**: Requirements for breach notification

### PCI DSS (Payment Card Industry Data Security Standard)

PCI DSS specifies security requirements for organizations handling payment card data.

**Applicable To**: Any entity storing, processing, or transmitting payment card data

**Key Requirements**:
- Firewall configuration
- Encryption of cardholder data
- Vulnerability management
- Access control
- Regular monitoring and testing

### NIST SP 800-218 (SSDF)

NIST SP 800-218 defines a Secure Software Development Framework (SSDF) with practices for secure development.

**Applicable To**: Software developers and integrators

**Practice Groups**:
- PO (Preparation & Organization): Policies, planning, tools
- PS (Protection & Security): Code review, security testing
- PO (Process Optimization): Defect identification, monitoring

## Control Mapping

### SOC 2 Common Criteria (CC) Controls

| Control | Requirement | Implementation | Evidence |
|---------|-------------|-----------------|----------|
| **CC6.1** | Logical Access Control | OIDC + RBAC with 5 roles | docs/ARCHITECTURE.md, WI-02 |
| **CC6.2** | Segregation of Duties (SoD) | Validator cannot approve own gates | WI-06, test_sod_enforcement |
| **CC6.3** | Restrict Auth Tokens | JWT with 15-min TTL, MFA step-up | WI-03, test_token_expiration |
| **CC6.4** | Encrypt Credentials | Ed25519 key derivation, PBKDF2 | WI-02, test_crypto |
| **CC6.5** | Restrict Physical Access | Not applicable (cloud-native) | N/A |
| **CC6.6** | Encryption of Data in Transit | TLS 1.3 enforced | ARCHITECTURE.md |
| **CC6.7** | Encryption of Data at Rest | PostgreSQL encrypted volumes, secrets vault | ARCHITECTURE.md |
| **CC7.1** | Monitoring & Alerting | Prometheus + Grafana, audit trail | WI-17, INCIDENT-RESPONSE.md |
| **CC7.2** | Incident Response | Documented procedures with SEV1-4 | INCIDENT-RESPONSE.md |
| **CC7.3** | Investigation & Testing | Automated security scanning (SAST, DAST) | CI/CD pipeline |
| **CC7.4** | Secure Development | Code review, testing, SAST scanning | CONTRIBUTING.md, QA.md |
| **CC8.1** | System Configuration & Change Management | Feature flags, zero-downtime deployment | WI-18, CHANGE-MANAGEMENT.md |
| **CC9.1** | Disaster Recovery & Continuity | RTO 4 hours, RPO 1 hour | ARCHITECTURE.md |

### ISO 27001:2022 Control Mapping

| Control ID | Control Name | Implementation | Status |
|-----------|-------------|-----------------|--------|
| **A.5.3** | Segregation of duties | RBAC + SoD validation (WI-06) | ✓ Implemented |
| **A.6.2** | User registration & access | OIDC provisioning via IdP | ✓ Implemented |
| **A.7.3** | Securing office supplies & equipment | Physical security of servers (hosting provider) | ✓ Dependent |
| **A.8.1** | Cryptography policy | Ed25519, TLS 1.3, AES-256 | ✓ Implemented |
| **A.8.2** | Cryptographic key management | JWKS publication, key rotation policy | ✓ Implemented |
| **A.8.3** | Separation of development & production | Infrastructure as code, separate envs | ✓ Implemented |
| **A.8.5** | Access control to cryptographic keys | Vault-based secrets management | ✓ Implemented |
| **A.8.6** | Developer machines | Not in scope (organization policy) | N/A |
| **A.8.23** | Restricting access to information | Row-level security via PostgreSQL views | ✓ Implemented |
| **A.8.28** | Software/firmware update management | Patching policy (SECURITY-EOL.md) | ✓ Implemented |
| **A.8.30** | Cryptographic controls effectiveness | Automated validation in tests | ✓ Implemented |

### GDPR Article Mapping

| Article | Requirement | Implementation | Status |
|---------|-------------|-----------------|--------|
| **Art. 5** | Data protection principles | Privacy by design (PII redaction, retention) | ✓ |
| **Art. 25** | Privacy by design | Minimal collection, encryption, access control | ✓ |
| **Art. 28** | Data processing agreements | DPA with Compliance Service | ✓ |
| **Art. 30** | Records of processing | Data Processing Register (DPIR) | ✓ |
| **Art. 32** | Security of processing | Encryption, access control, monitoring | ✓ |
| **Art. 33** | Breach notification (72h) | Incident response procedures | ✓ |
| **Art. 34** | Communication to data subjects | Notification templates prepared | ✓ |
| **Art. 35** | DPIA (Data Protection Impact Assessment) | DPIA template available | ✓ |
| **Art. 36** | Prior consultation (EDPB) | Process documented | ✓ |

### HIPAA Security Rule Mapping

| Safeguard | Requirement | Implementation | Status |
|-----------|-------------|-----------------|--------|
| **Administrative** | Workforce security | OIDC + IdP-enforced policies | ✓ |
| **Administrative** | Information access mgmt | RBAC with role-based row-level security | ✓ |
| **Administrative** | Workforce security training | Organization responsibility | ✓ |
| **Technical** | Access controls | OIDC + JWT + MFA step-up | ✓ |
| **Technical** | Audit controls | Immutable audit log (PostgreSQL triggers) | ✓ |
| **Technical** | Integrity controls | Cryptographic signatures on audit entries | ✓ |
| **Technical** | Transmission security | TLS 1.3 + encrypted vault | ✓ |
| **Physical** | Facility access controls | Hosting provider responsibility | ✓ |
| **Physical** | Equipment & media controls | Secure deletion policy | ✓ |

### PCI DSS Control Mapping

| Requirement | Requirement Name | Implementation | Status |
|-------------|------------------|-----------------|--------|
| **1** | Firewall configuration | WAF + network ACLs (hosting) | ✓ |
| **2** | Remove default passwords | OIDC + no default credentials | ✓ |
| **3** | Protect stored card data | No card data stored (out of scope) | N/A |
| **4** | Encrypt cardholder data in transit | TLS 1.3 enforced | ✓ |
| **6** | Develop secure applications | SAST + DAST + code review | ✓ |
| **7** | Restrict access to data | RBAC + SoD enforcement | ✓ |
| **8** | Identify & authenticate access | OIDC + MFA available | ✓ |
| **10** | Track & monitor access | Audit logging + monitoring | ✓ |
| **12** | Maintain security policy | Policy documented (SECURITY.md) | ✓ |

## Evidence Collection

### Audit Evidence Artifacts

Evidence artifacts collected during operation for audit verification:

```
compliance/
├── audit-logs/                          # Immutable audit trail
│   ├── 2024-04-27-audit-entries.json   # Daily audit export
│   └── 2024-04-26-audit-entries.json   # Previous days
│
├── security-scans/                      # Security assessment results
│   ├── sast-report-2024-04-27.sarif    # Semgrep static analysis
│   ├── dast-report-2024-04-20.html     # OWASP ZAP scan
│   ├── dependency-scan-2024-04-27.json # Grype vulnerability scan
│   └── container-scan-latest.json      # Trivy container image scan
│
├── access-logs/                         # Authentication/authorization evidence
│   ├── oidc-logins-2024-04-27.log      # OIDC login events
│   ├── mfa-steps-2024-04-27.log        # MFA verification events
│   └── rbac-decisions-2024-04-27.json  # Access control decisions
│
├── compliance-assessments/               # Compliance evaluations
│   ├── iso27001-self-assessment-2024.xlsx
│   ├── gdpr-dpia-template.pdf
│   ├── hipaa-risk-assessment-2024.docx
│   └── pci-dss-readiness-checklist.xlsx
│
├── change-logs/                         # Change management evidence
│   ├── deployment-log-2024-04-27.txt   # Deployment details
│   ├── rollback-log-2024-04-10.txt     # Rollback procedures
│   └── code-review-summaries-2024.xlsx # PR review evidence
│
├── incident-records/                    # Incident response evidence
│   ├── incident-2024-04-15-summary.md  # Incident report
│   ├── incident-2024-04-15-timeline.txt # Event timeline
│   └── incident-2024-04-15-postmortem.md # Lessons learned
│
└── certifications/                       # Compliance certifications
    ├── soc2-audit-report-2024.pdf
    ├── iso27001-certificate-2024.pdf
    └── penetration-test-2024.pdf
```

### Automated Evidence Collection

Evidence is collected continuously via:

| Evidence Type | Source | Frequency | Format |
|---------------|--------|-----------|--------|
| **Audit Logs** | Application (immutable) | Continuous | JSON |
| **Access Logs** | PostgreSQL audit triggers | Per transaction | Binary log |
| **Security Scans** | CI/CD pipeline (Semgrep, Grype) | Daily | SARIF, JSON |
| **Deployment Records** | kubectl audit log | Per deployment | JSON |
| **Test Results** | CI/CD (pytest, coverage) | Per commit | JUnit XML |
| **Configuration** | Git history (signed commits) | Per change | Git objects |
| **Vulnerability Reports** | Trivy, pip-audit | Weekly | JSON |

## Audit Artifacts

### SOC 2 Type II Audit Package

For SOC 2 audits, the following artifacts are prepared:

1. **System Design & Implementation** (ARCHITECTURE.md)
   - System boundaries and trust zones
   - Network topology and data flows
   - Cryptographic implementations
   - Authentication & authorization mechanisms

2. **Policy & Procedures** (SECURITY.md, CHANGE-MANAGEMENT.md, etc.)
   - Information security policy
   - Change management procedures
   - Incident response playbooks
   - Access control policies
   - Data retention policies

3. **Audit Evidence** (logs, screenshots, test results)
   - Access control logs (logins, privilege escalations)
   - Change approval records (PRs, code reviews)
   - Incident response records (tickets, timeline, resolution)
   - Vulnerability scan results (SAST, DAST, dependency)
   - Test coverage reports (pytest coverage)

4. **Certifications & Assessments**
   - Penetration test results
   - Security vulnerability assessment
   - Business continuity & disaster recovery test results

### ISO 27001 Audit Package

For ISO 27001 certification, these artifacts are compiled:

1. **Statement of Applicability (SoA)**
   - List of 93 ISO 27001 controls
   - Assessment of applicability (applicable/not applicable)
   - Implementation status (implemented/in progress/not implemented)
   - Evidence references for each control

2. **Risk Assessment Report**
   - Risk identification (asset, threat, vulnerability)
   - Risk analysis (likelihood, impact)
   - Risk evaluation (acceptable/unacceptable)
   - Risk treatment plan (mitigate/accept/avoid)

3. **Control Documentation**
   - Control descriptions
   - Responsibility assignments
   - Implementation evidence
   - Effectiveness verification

4. **Management Review Records**
   - Annual ISMS review minutes
   - Corrective action log
   - Performance metrics (KPIs)

### GDPR Compliance Documentation

For GDPR compliance verification:

1. **Data Processing Agreement (DPA)**
   - Processor/controller roles
   - Processing instructions & limitations
   - Security measures
   - Sub-processor management
   - Data subject rights support

2. **Data Protection Impact Assessment (DPIA)**
   - Processing description
   - Necessity & legitimacy assessment
   - Risk analysis
   - Risk mitigation measures

3. **Data Inventory & Retention Policy**
   - Personal data categories
   - Retention periods per category
   - Deletion procedures
   - Archival procedures

4. **Data Subject Rights Procedures**
   - Access request handling (DSR)
   - Deletion request handling (right to be forgotten)
   - Rectification procedures
   - Portability procedures

## Certification Status

### Current Certifications

| Certification | Type | Status | Valid Until | Auditor |
|---------------|------|--------|-------------|---------|
| **SOC 2 Type II** | Trust Services | Pending | TBD | [TBD] |
| **ISO 27001:2022** | Information Security | In Progress | TBD | [TBD] |
| **GDPR Ready** | Data Protection | Self-Assessed | N/A | Internal CISO |
| **HIPAA Ready** | Healthcare Privacy | Self-Assessed | N/A | Internal CISO |
| **PCI DSS** | Payment Security | Not Applicable | N/A | N/A (no card data) |

### Scheduled Audits

- **SOC 2 Type II**: Scheduled for Q3 2024 (6-month audit period Q2-Q3 2024)
- **ISO 27001**: Scheduled for Q4 2024 (assessment against 93 controls)
- **Annual Security Assessment**: Scheduled for Q2 2024 (penetration test + vulnerability assessment)

## Related Documents

- **ARCHITECTURE.md** — System design and security controls
- **SECURITY.md** — Vulnerability reporting and response procedures
- **SECURITY-EOL.md** — Security patch timeline and version support
- **CHANGE-MANAGEMENT.md** — Change control procedures
- **INCIDENT-RESPONSE.md** — Incident response procedures with evidence collection
- **DEPENDENCIES.md** — Dependency management and licensing compliance
- **QA.md** — Testing strategy and quality gates

---

**Last Updated**: 2024-04-27 | **Compliance Officer**: [Name] | **Next Audit**: Q3 2024 (SOC 2)
