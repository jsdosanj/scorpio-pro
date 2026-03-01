"""NIST Cybersecurity Framework 2.0 compliance mapping."""

from __future__ import annotations

from scorpio_pro.compliance.engine import BaseComplianceFramework


class NISTCSFCompliance(BaseComplianceFramework):
    """NIST Cybersecurity Framework 2.0 compliance evaluator.

    NIST CSF 2.0 organises cybersecurity activities into six functions:
    Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS),
    and Recover (RC).
    """

    name = "NIST CSF 2.0"
    description = (
        "NIST Cybersecurity Framework 2.0 — voluntary framework for managing "
        "and reducing cybersecurity risk, applicable to all sectors and organisation sizes."
    )

    controls = {
        # Govern
        "NIST-CSF-GV.OC-1": {
            "title": "Organisational Context",
            "description": "The organisational mission is understood and informs cybersecurity risk management.",
            "remediation": "Document organisational cybersecurity mission and risk tolerance.",
        },
        "NIST-CSF-GV.RM-1": {
            "title": "Risk Management Strategy",
            "description": "Risk management objectives are established and agreed to by organisational stakeholders.",
            "remediation": "Establish and document a formal risk management strategy.",
        },
        # Identify
        "NIST-ID.AM-1": {
            "title": "Asset Management — Physical Devices",
            "description": "Physical devices and systems within the organisation are inventoried.",
            "remediation": "Maintain an up-to-date inventory of all hardware assets.",
        },
        "NIST-ID.AM-2": {
            "title": "Asset Management — Software",
            "description": "Software platforms and applications within the organisation are inventoried.",
            "remediation": "Maintain an authorised software inventory; remove unneeded software.",
        },
        "NIST-ID.AM-3": {
            "title": "Asset Management — Network",
            "description": "Organisational communication and data flows are mapped.",
            "remediation": "Create and maintain network topology diagrams and data flow maps.",
        },
        "NIST-ID.RA-1": {
            "title": "Risk Assessment — Vulnerabilities",
            "description": "Asset vulnerabilities are identified and documented.",
            "remediation": "Conduct regular vulnerability assessments and penetration tests.",
        },
        # Protect
        "NIST-PR.AC-1": {
            "title": "Identity Management — Credentials",
            "description": "Identities and credentials are issued, managed, verified, revoked, and audited.",
            "remediation": "Implement strong password policies, MFA, and regular credential audits.",
        },
        "NIST-PR.AC-3": {
            "title": "Remote Access Management",
            "description": "Remote access is managed.",
            "remediation": "Enforce VPN/MFA for remote access; audit remote sessions.",
        },
        "NIST-PR.AC-5": {
            "title": "Network Integrity Protection",
            "description": "Network integrity is protected, incorporating network segregation where appropriate.",
            "remediation": "Segment networks; apply firewall rules; disable unnecessary services.",
        },
        "NIST-PR.AC-7": {
            "title": "Users, Devices, and Assets — Authentication",
            "description": "Users, devices, and other assets are authenticated commensurate with the risk of the transaction.",
            "remediation": "Deploy MFA on all systems, especially privileged and remote access.",
        },
        "NIST-PR.DS-1": {
            "title": "Data at Rest Protection",
            "description": "Data-at-rest is protected.",
            "remediation": "Encrypt sensitive data at rest using AES-256 or equivalent.",
        },
        "NIST-PR.DS-2": {
            "title": "Data in Transit Protection",
            "description": "Data-in-transit is protected.",
            "remediation": "Use TLS 1.2+ for all data transmissions; disable cleartext protocols.",
        },
        "NIST-PR.IP-1": {
            "title": "Baseline Configuration",
            "description": "A baseline configuration of IT/OT systems is created and maintained.",
            "remediation": "Document and enforce security baselines for all systems.",
        },
        "NIST-PR.IP-12": {
            "title": "Vulnerability Management",
            "description": "A vulnerability management plan is developed and implemented.",
            "remediation": "Establish patch management SLAs: Critical ≤ 24h, High ≤ 7 days.",
        },
        # Detect
        "NIST-DE.CM-3": {
            "title": "Personnel Activity Monitoring",
            "description": "Personnel activity is monitored to detect potential cybersecurity events.",
            "remediation": "Deploy SIEM and enable audit logging across all critical systems.",
        },
        "NIST-DE.CM-4": {
            "title": "Malicious Code Detection",
            "description": "Malicious code is detected.",
            "remediation": "Deploy endpoint protection and regularly scan for malware.",
        },
        # Respond
        "NIST-RS.RP-1": {
            "title": "Response Planning",
            "description": "Response plan is executed during or after an incident.",
            "remediation": "Develop, test, and maintain an incident response plan.",
        },
        # Recover
        "NIST-RC.RP-1": {
            "title": "Recovery Planning",
            "description": "Recovery plan is executed during or after a cybersecurity incident.",
            "remediation": "Develop and regularly test a disaster recovery / business continuity plan.",
        },
        # Additional CSF-tagged controls
        "NIST-CSF-PR.DS-2": {
            "title": "Data in Transit Protection (CSF tag)",
            "description": "Data in transit is protected.",
            "remediation": "Use TLS 1.2+ and disable weak cipher suites.",
        },
        "NIST-CSF-PR.IP-1": {
            "title": "Baseline Configurations (CSF tag)",
            "description": "Baseline configurations are maintained.",
            "remediation": "Enforce security baselines and configuration management.",
        },
        "NIST-CSF-PR.IP-12": {
            "title": "Vulnerability Management (CSF tag)",
            "description": "Vulnerabilities are identified and remediated.",
            "remediation": "Implement a continuous vulnerability management programme.",
        },
        "NIST-CSF-PR.PT-3": {
            "title": "Least Functionality",
            "description": "Systems operate at minimum required functionality.",
            "remediation": "Disable all unnecessary services, ports, and protocols.",
        },
    }
