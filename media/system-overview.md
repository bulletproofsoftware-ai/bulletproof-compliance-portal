# Technical Briefing: bulletproof-compliance-portal

### 1. Executive System Overview
The `bulletproof-compliance-portal` is a FastAPI-based governance interface designed to provide a human-centric orchestration layer over a backing compliance service. It centralizes regulatory workflows—including Data Subject Requests (DSRs), audit trail exploration, and gate decision management—for compliance officers, external auditors, and domain experts.

#### The Three Surfaces
The application architecture supports three logical surfaces through distinct deployment configurations:

| Application Mode (`APP_MODE`) | Surface | Primary Purpose | Target Audience |
| :--- | :--- | :--- | :--- |
| `internal` | **Internal Portal** | Comprehensive workspace for triage, evidence review, and reporting. | Compliance Officers, SMEs, Admins |
| `public` | **Public DSR Portal** | Self-service intake for GDPR Articles 15–22 requests. | Data Subjects |
| `internal` (Scoped) | **Auditor Access** | Restricted, time-limited retrieval of evidence and audit chains. | External Auditors |

#### Core Functional Capabilities
*   **DSR Management:** End-to-end handling of data subject requests, utilizing an identity-verification state machine (AMD-01) and evidence delivery within 30-day windows.
*   **Gate Decision Workspace:** Centralized interface for evidence review and recording gate decisions with enforced Separation of Duties (SoD).
*   **Audit Exploration:** Capability to search, filter, and download tamper-evident audit trails with integrated integrity verification.
*   **Regulatory Report Generation:** Assembly and approval of reports resulting in Ed25519-signed delivery bundles.

---

### 2. Architecture and Component Design

#### Dual-Mode Application Factory
The system utilizes a single codebase with an application factory (`create_app(mode=...)`) to generate two distinct deployment images. 
*   **`Dockerfile.portal`**: Deploys the internal workspace with the full suite of 14 routers.
*   **`Dockerfile.dsr_portal`**: Deploys a hardened, public-facing version. In `public` mode, OpenAPI documentation (`/docs`, `/redoc`, `/openapi.json`) is explicitly disabled, and only the DSR intake and health routers are mounted to minimize the attack surface.

#### System Component Hierarchy
*   **FastAPI Applications:** The core logic layer managing request routing, business logic, and RBAC enforcement.
*   **Nginx Reverse Proxies:** Acts as the entry point for both portals, handling TLS termination and forwarding headers.
*   **Redis Session Store:** Facilitates session persistence across multi-worker deployments and maintains rate-limit counters.
*   **PostgreSQL Database:** Provides the primary asynchronous persistence layer for portal-specific state and metadata.
*   **External Compliance Service:** The authoritative system of record, accessed via the portal's client using mTLS.

#### Router Architecture
The internal portal features 81 routes distributed across 14 specialized routers, while the public portal is restricted to 8 routes.

**Internal Portal Router Mapping:**
| Prefix | Business Domain | Router ID |
| :--- | :--- | :--- |
| `/audit` | Audit explorer and integrity verification | WI-04 |
| `/evidence` | Evidence package library and watermarked downloads | WI-05 |
| `/gates` | Gate decision workspace and MFA step-up | WI-06 |
| `/admin/auditor-engagements` | Provisioning and scoping of external auditor access | WI-07 |
| `/dsr` | Internal triage and management of DSRs | WI-08 |
| `/incidents` | Incident tracking (NY DFS 72-hour clocks) | WI-10 |
| `/models` | Model-card registry and annual sign-off tracking | WI-11 |
| `/reports` | Generation and Ed25519-signing of reports | WI-12 |
| `/dashboards` | SLA compliance and risk heatmaps | WI-13 |
| `/knowledge` | Process-knowledge verification (SME review) | WI-14 |
| `/outcomes` | KPI and outcome economics tracking | WI-15 |
| `/projects` | Read-only architecture and documentation portal | WI-16 |
| `/auth` | OIDC authentication and callback handlers | - |
| `/export` | PDF export service with SSRF protection | - |

---

### 3. Security Architecture and Compliance Controls

#### Authentication and RBAC Model
The system employs OIDC with the PKCE authorization-code flow. Identity Provider (IdP) group claims are mapped to five system roles: `admin`, `compliance_officer`, `auditor`, `sme`, and `viewer`.

#### Multi-Factor Authentication (MFA) Step-Up
Sensitive operations (gate decisions, report signing, and model sign-off) trigger a mandatory MFA step-up (AMD-03).
*   **Mechanism:** A short-lived nonce is issued upon page render and cryptographically bound to the `user_sub` and `resource_id`.
*   **Lifecycle:** The nonce has a strict 60-second lifetime.
*   **Integrity:** The nonce is consumed upon use to prevent replay; any rejected or replayed nonce triggers an immediate audit event.

#### Data Protection and Privacy Controls
*   **PII Redaction (AMD-17):** A custom `structlog` redactor masks sensitive fields in logs (e.g., `subject_email`, `subject_name`, `subject_phone`, `subject_address`, `dob`) at any nesting depth.
*   **PDF SSRF Protection (AMD-02):** The export service utilizes a safe URL fetcher with a scheme whitelist. The use of the `|safe` filter in templates is strictly prohibited.
*   **Audit Immutability (REQ-CPL-039):** Enforcement is dual-layered:
    *   **Static:** CI/CD "ruff" rules ban the use of `audit_events.insert()` or `audit_events.update()` within portal code.
    *   **Runtime:** Middleware blocks all write requests to the `/audit_events/*` path.
*   **Cryptographic Signing (AMD-04):** Reports are Ed25519-signed and anchored to a JWKS. To ensure operational continuity, a **90-day overlap window** is maintained for key rotation, allowing old keys to remain valid while new keys propagate.

---

### 4. Deployment and Operational Management

#### Deployment Modes and Network Isolation
*   **Internal Portal:** Must be deployed on a private/overlay network. It is not intended for internet exposure.
*   **Public Portal:** Exposed to the internet via a WAF for protection and rate limiting.

#### Minimum Configuration
| Variable | Purpose |
| :--- | :--- |
| `SESSION_SECRET` | 32-byte random string for session/CSRF signing. |
| `COMPLIANCE_API_TOKEN` | Bearer token for the backing service. |
| `OIDC_CLIENT_ID` / `OIDC_ISSUER` | OIDC client identifier and provider issuer URL. |
| `OIDC_REDIRECT_URI` | Registered callback (e.g., `/auth/callback`). |
| `APP_MODE` / `APP_ENV` | Deployment mode (`internal`/`public`) and environment. |
| `REDIS_URL` / `PG_DSN` | Connection strings for Redis and PostgreSQL. |

#### Observability and Secret Management
*   **Health:** `/healthz` (liveness) and `/readyz` (readiness) endpoints are wired to container health checks.
*   **Hardening:** Images run as a **non-root user (10001:10001)** and use **`tini` as PID 1**.
*   **Secrets:** Secrets must be file-mounted into containers at runtime; baking secrets into images is prohibited.

---

### 5. Role-Based Workflows and Usage

#### Separation of Duties (SoD) Enforcement
The portal programmatically prevents a single user from completing conflicting stages of a workflow:
*   **DSRs:** Users cannot identity-verify a DSR they submitted.
*   **Reports:** Users cannot approve a regulatory report they authored.
*   **Gate Decisions:** Approvals are blocked if the submitter is the same as the requester.

#### Specialized Workflows
*   **Domain Expert (SME):** SMEs review process-knowledge candidates. For any modification, the system enforces a **rationale of at least 30 characters** before the knowledge is forwarded.
*   **Auditor Provisioning:** Admins create time-limited, scope-enforced engagements. Evidence PDFs downloaded by auditors are **watermarked with the unique identity** of the auditor for non-repudiation.
*   **Public DSR Intake:** Includes a CAPTCHA-protected intake form and an identity-verification state machine that handles document validation and metadata checks.

---

### 6. API and Integration Reference

#### Portal-to-Service Communication
The portal communicates with the backing service via mTLS. This requires the following environment variables:
*   `COMPLIANCE_API_CLIENT_CERT`: Client certificate path.
*   `COMPLIANCE_API_CLIENT_KEY`: Client key path.
*   `COMPLIANCE_API_CA_BUNDLE`: CA bundle for service certificate verification.

#### Middleware Stack Order
Every request passes through a fixed middleware chain, registered in the following sequence:
1.  **forwarded-headers** (X-Forwarded-*)
2.  **request ID** (Correlation tracking)
3.  **security headers** (CSP, HSTS, X-Frame-Options)
4.  **CORS**
5.  **rate limiting** (Redis-backed)
6.  **CSRF** (Session-bound)
7.  **audit logging** (AMD-17)
8.  **behavioral hook**

To prevent session fixation (AMD-15), the system automatically rotates the session ID upon every successful OIDC callback.