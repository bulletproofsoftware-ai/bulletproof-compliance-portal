"""Public DSR Portal — WI-09.

Architecturally separate FastAPI application running in its own container, on
its own domain, exposed to the public internet. Provides self-service GDPR
DSR submission, status check, identity-proof upload, and receipt download.

NO authentication state is shared with the internal portal. NO direct database
access. All operations go through the WI-03 ComplianceClient with a separate
service-account token whose ACL (AMD-05) restricts it to four operations:

    SUBMIT             — submit_dsr_request(source="public")
    STATUS_CHECK       — get_dsr_request_public(reference, email)
    IDENTITY_UPLOAD    — upload_identity_proof(...)
    RECEIPT_DOWNLOAD   — get_dsr_receipt(...)

Any other operation MUST be rejected by the compliance service with
`403 service_account_acl_violation`. The portal additionally enforces the ACL
client-side via TokenCapability (defense in depth).
"""

from .main import create_public_app

__all__ = ["create_public_app"]
