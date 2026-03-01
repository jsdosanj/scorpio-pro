"""GDPR compliance framework — maps findings to GDPR Article requirements."""

from __future__ import annotations

from scorpio_pro.compliance.engine import BaseComplianceFramework


class GDPRCompliance(BaseComplianceFramework):
    """General Data Protection Regulation (GDPR) compliance evaluator.

    Covers the technical and organisational measures (Article 32) and key
    data subject rights and controller obligations relevant to security assessments.
    """

    name = "GDPR"
    description = (
        "EU General Data Protection Regulation (Regulation 2016/679). "
        "Applies to processing of personal data of EU/EEA data subjects."
    )

    controls = {
        "GDPR-Art32": {
            "title": "Art. 32 — Security of Processing",
            "description": (
                "Implement appropriate technical and organisational measures to ensure a level "
                "of security appropriate to the risk, including encryption, confidentiality, "
                "integrity, and availability."
            ),
            "remediation": (
                "Implement encryption at rest and in transit, access controls, "
                "vulnerability management, and regular security testing."
            ),
        },
        "GDPR-Art33": {
            "title": "Art. 33 — Breach Notification to Supervisory Authority",
            "description": "Notify the supervisory authority within 72 hours of becoming aware of a personal data breach.",
            "remediation": "Implement breach detection capabilities and a documented incident response procedure with 72-hour notification workflow.",
        },
        "GDPR-Art34": {
            "title": "Art. 34 — Communication of Breach to Data Subject",
            "description": "Communicate a high-risk personal data breach to affected data subjects without undue delay.",
            "remediation": "Develop data subject breach notification templates and communication procedures.",
        },
        "GDPR-Art5": {
            "title": "Art. 5 — Data Minimisation and Purpose Limitation",
            "description": "Personal data shall be collected for specified, explicit, and legitimate purposes and not processed beyond those purposes.",
            "remediation": "Review data collection practices; document purpose limitation and data minimisation policies.",
        },
        "GDPR-Art17": {
            "title": "Art. 17 — Right to Erasure",
            "description": "Data subjects have the right to obtain erasure of their personal data without undue delay.",
            "remediation": "Implement data deletion workflows that cover all data stores, backups, and third-party processors.",
        },
        "GDPR-Art25": {
            "title": "Art. 25 — Data Protection by Design and Default",
            "description": "Implement data protection principles into the design of processing activities.",
            "remediation": "Apply privacy-by-design principles; default to privacy-preserving settings.",
        },
        "GDPR-Art28": {
            "title": "Art. 28 — Data Processing Agreements",
            "description": "Where processing is carried out by a processor, a Data Processing Agreement (DPA) must be in place.",
            "remediation": "Audit all third-party vendors; ensure DPAs are signed with all data processors.",
        },
        "GDPR-Art30": {
            "title": "Art. 30 — Records of Processing Activities",
            "description": "Maintain a record of all processing activities under the controller's responsibility.",
            "remediation": "Create and maintain a Record of Processing Activities (RoPA).",
        },
        "GDPR-Art35": {
            "title": "Art. 35 — Data Protection Impact Assessment",
            "description": "Conduct a DPIA where processing is likely to result in high risk to data subjects.",
            "remediation": "Identify processing activities requiring DPIA; conduct and document assessments.",
        },
        "GDPR-Art37": {
            "title": "Art. 37 — Data Protection Officer",
            "description": "Designate a Data Protection Officer where required by Article 37.",
            "remediation": "Assess whether a DPO is required; appoint and register the DPO with the supervisory authority.",
        },
        "GDPR-Art44": {
            "title": "Art. 44-49 — Cross-Border Data Transfers",
            "description": "Transfers of personal data to third countries must be protected by appropriate safeguards.",
            "remediation": "Use Standard Contractual Clauses, Binding Corporate Rules, or an adequacy decision for transfers outside the EEA.",
        },
    }
