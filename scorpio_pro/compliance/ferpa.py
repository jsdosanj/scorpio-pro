"""FERPA compliance framework — maps findings to FERPA requirements."""

from __future__ import annotations

from scorpio_pro.compliance.engine import BaseComplianceFramework


class FERPACompliance(BaseComplianceFramework):
    """Family Educational Rights and Privacy Act (FERPA) compliance evaluator.

    FERPA (20 U.S.C. § 1232g; 34 CFR Part 99) protects the privacy of
    student education records.  This evaluator maps technical security
    controls to FERPA's data protection expectations.
    """

    name = "FERPA"
    description = (
        "Family Educational Rights and Privacy Act (20 U.S.C. § 1232g). "
        "Governs access to educational records maintained by institutions "
        "receiving federal funding."
    )

    controls = {
        "FERPA-access": {
            "title": "Student Data Access Controls",
            "description": "Restrict access to education records to authorised school officials with legitimate educational interest.",
            "remediation": "Implement role-based access control; restrict student record access to authorised personnel only.",
        },
        "FERPA-authentication": {
            "title": "Authentication Strength",
            "description": "Ensure only authorised individuals can access student records through strong authentication.",
            "remediation": "Enforce MFA on all student information systems (SIS).",
        },
        "FERPA-data-sharing": {
            "title": "Data Sharing Controls",
            "description": "Student records may only be disclosed under limited circumstances (consent, legitimate exception).",
            "remediation": "Audit data sharing integrations; ensure proper consent/exception documentation.",
        },
        "FERPA-logging": {
            "title": "Access Logging",
            "description": "Maintain records of all disclosures of personally identifiable information from education records.",
            "remediation": "Enable and retain audit logs for all access to student education records.",
        },
        "FERPA-encryption": {
            "title": "Data Encryption",
            "description": "Protect student records with encryption at rest and in transit.",
            "remediation": "Encrypt student databases at rest; use TLS 1.2+ for all transmissions.",
        },
        "FERPA-breach-notification": {
            "title": "Breach Notification Readiness",
            "description": "Have procedures to notify affected students and institutions in case of a data breach.",
            "remediation": "Establish an incident response plan including FERPA breach notification procedures.",
        },
        "FERPA-vendor-agreements": {
            "title": "Third-Party Vendor Agreements",
            "description": "Ensure third-party vendors acting as school officials have appropriate data use agreements.",
            "remediation": "Review and update all vendor contracts to include FERPA-compliant data use provisions.",
        },
    }
