"""NIST AI Risk Management Framework compliance mapping."""

from __future__ import annotations

from scorpio_pro.compliance.engine import BaseComplianceFramework


class NISTAICompliance(BaseComplianceFramework):
    """NIST AI Risk Management Framework (AI RMF 1.0) compliance evaluator.

    The NIST AI RMF organises AI risk management into four functions:
    Map, Measure, Manage, and Govern.
    """

    name = "NIST AI RMF"
    description = (
        "NIST AI Risk Management Framework 1.0 — voluntary guidance for "
        "managing risks associated with the design, development, deployment, "
        "and operation of AI systems."
    )

    controls = {
        "NIST-AI-GOV-1": {
            "title": "AI Governance Policies",
            "description": "Organisational policies governing AI risk management are established and communicated.",
            "remediation": "Establish an AI governance policy covering accountability, ethics, and risk tolerance.",
        },
        "NIST-AI-GOV-2": {
            "title": "AI Inventory",
            "description": "An inventory of AI systems in use by the organisation is maintained.",
            "remediation": "Create and maintain a registry of all AI/ML models deployed in production.",
        },
        "NIST-AI-MAP-1": {
            "title": "AI Context Establishment",
            "description": "The context in which an AI system will be deployed is established and documented.",
            "remediation": "Document intended use cases, user populations, and environmental constraints for each AI system.",
        },
        "NIST-AI-MAP-2": {
            "title": "AI Risk Identification",
            "description": "Risks associated with AI systems are identified and categorised.",
            "remediation": "Conduct AI-specific risk assessments covering bias, safety, security, and privacy.",
        },
        "NIST-AI-MEASURE-1": {
            "title": "Model Security Assessment",
            "description": "AI models are assessed for adversarial vulnerabilities.",
            "remediation": "Test AI models for adversarial inputs, model inversion, and membership inference attacks.",
        },
        "NIST-AI-MEASURE-2": {
            "title": "Data Pipeline Integrity",
            "description": "Training and inference data pipelines are secured against tampering.",
            "remediation": "Implement data provenance tracking; validate data integrity before training/inference.",
        },
        "NIST-AI-MEASURE-3": {
            "title": "Bias and Fairness Testing",
            "description": "AI systems are evaluated for bias that could lead to unfair or discriminatory outcomes.",
            "remediation": "Conduct regular fairness audits using diverse test datasets; document bias mitigation measures.",
        },
        "NIST-AI-MANAGE-1": {
            "title": "AI Risk Treatment",
            "description": "Identified AI risks are treated through mitigation, transfer, or acceptance.",
            "remediation": "Implement a formal AI risk register and assign ownership of each identified risk.",
        },
        "NIST-AI-MANAGE-2": {
            "title": "AI System Monitoring",
            "description": "AI systems in production are continuously monitored for performance degradation and anomalies.",
            "remediation": "Deploy model monitoring solutions; alert on distribution shift, accuracy drops, and anomalies.",
        },
        "NIST-AI-MANAGE-3": {
            "title": "AI Incident Response",
            "description": "Processes exist for responding to AI system incidents.",
            "remediation": "Include AI-specific scenarios in the organisation's incident response plan.",
        },
    }
