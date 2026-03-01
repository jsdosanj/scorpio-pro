"""HIPAA compliance framework — maps findings to HIPAA Security Rule controls."""

from __future__ import annotations

from scorpio_pro.compliance.engine import BaseComplianceFramework


class HIPAACompliance(BaseComplianceFramework):
    """HIPAA Security Rule (45 CFR Part 164) compliance evaluator.

    Covers the key Technical Safeguard and Administrative Safeguard controls
    relevant to technical security assessments.
    """

    name = "HIPAA"
    description = (
        "Health Insurance Portability and Accountability Act — Security Rule (45 CFR Part 164). "
        "Applies to covered entities and business associates handling ePHI."
    )

    controls = {
        "HIPAA-164.308(a)(1)": {
            "title": "Security Management Process",
            "description": "Implement policies and procedures to prevent, detect, contain, and correct security violations.",
            "remediation": "Establish a formal security risk analysis and risk management program.",
        },
        "HIPAA-164.308(a)(5)": {
            "title": "Security Awareness and Training",
            "description": "Implement a security awareness and training program for all workforce members.",
            "remediation": "Deploy security awareness training covering phishing, password hygiene, and data handling.",
        },
        "HIPAA-164.308(a)(5)(ii)(A)": {
            "title": "Protection from Malicious Software",
            "description": "Procedures for guarding against, detecting, and reporting malicious software.",
            "remediation": "Deploy and maintain endpoint protection (AV/EDR) on all systems handling ePHI.",
        },
        "HIPAA-164.308(a)(5)(ii)(B)": {
            "title": "Malicious Software Protection",
            "description": "Implement procedures to guard against, detect, and report malicious software.",
            "remediation": "Ensure AV/EDR is installed, active, and regularly updated.",
        },
        "HIPAA-164.312(a)(1)": {
            "title": "Access Control",
            "description": "Implement technical policies and procedures for electronic information systems to allow access only to authorized persons or software.",
            "remediation": "Implement role-based access control and principle of least privilege.",
        },
        "HIPAA-164.312(a)(2)(i)": {
            "title": "Unique User Identification",
            "description": "Assign a unique name and/or number for identifying and tracking user identity.",
            "remediation": "Ensure every user account is unique; prohibit shared accounts.",
        },
        "HIPAA-164.312(a)(2)(iii)": {
            "title": "Automatic Logoff",
            "description": "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.",
            "remediation": "Configure session timeouts ≤ 15 minutes on all systems handling ePHI.",
        },
        "HIPAA-164.312(a)(2)(iv)": {
            "title": "Encryption and Decryption",
            "description": "Implement a mechanism to encrypt and decrypt electronic protected health information.",
            "remediation": "Enable full-disk encryption and encrypt ePHI at rest and in transit.",
        },
        "HIPAA-164.312(b)": {
            "title": "Audit Controls",
            "description": "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems containing ePHI.",
            "remediation": "Enable comprehensive audit logging on all systems handling ePHI. Retain logs ≥ 6 years.",
        },
        "HIPAA-164.312(d)": {
            "title": "Person or Entity Authentication",
            "description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
            "remediation": "Deploy MFA on all systems and applications that access ePHI.",
        },
        "HIPAA-164.312(e)(1)": {
            "title": "Transmission Security",
            "description": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic communications network.",
            "remediation": "Use TLS 1.2+ for all network transmissions of ePHI. Disable legacy protocols.",
        },
        "HIPAA-164.312(e)(2)(ii)": {
            "title": "Encryption in Transit",
            "description": "Implement a mechanism to encrypt ePHI whenever deemed appropriate.",
            "remediation": "Use TLS 1.2+ with strong cipher suites for all ePHI transmission.",
        },
    }
