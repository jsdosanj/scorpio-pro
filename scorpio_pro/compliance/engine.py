"""Compliance engine — maps findings to frameworks and calculates scores."""

from __future__ import annotations

from typing import Any

from scorpio_pro.scanners.base_scanner import Finding


class ComplianceEngine:
    """Evaluates security findings against multiple compliance frameworks.

    Frameworks supported:
    - HIPAA
    - FERPA
    - NIST CSF 2.0
    - NIST AI RMF
    - GDPR

    For each framework, the engine:
    1. Identifies which findings map to which controls.
    2. Calculates a compliance score (0–100).
    3. Identifies gaps (controls with failing findings).
    4. Produces remediation recommendations.
    """

    def evaluate(self, findings: list[Finding]) -> dict[str, Any]:
        """Evaluate all findings against all supported frameworks.

        Args:
            findings: List of :class:`~scorpio_pro.scanners.base_scanner.Finding` objects.

        Returns:
            Dict mapping framework name to evaluation results.
        """
        from scorpio_pro.compliance.hipaa import HIPAACompliance
        from scorpio_pro.compliance.ferpa import FERPACompliance
        from scorpio_pro.compliance.nist_csf import NISTCSFCompliance
        from scorpio_pro.compliance.nist_ai import NISTAICompliance
        from scorpio_pro.compliance.gdpr import GDPRCompliance

        frameworks = [
            HIPAACompliance(),
            FERPACompliance(),
            NISTCSFCompliance(),
            NISTAICompliance(),
            GDPRCompliance(),
        ]

        results: dict[str, Any] = {}
        for fw in frameworks:
            results[fw.name] = fw.evaluate(findings)

        return results


class BaseComplianceFramework:
    """Abstract base for compliance framework evaluators.

    Subclasses define :attr:`controls` — a mapping of control ID to metadata.
    """

    #: Human-readable framework name.
    name: str = "BaseFramework"
    #: Short description.
    description: str = ""

    # controls: {control_id: {"title": str, "description": str, "tags": [str]}}
    controls: dict[str, dict[str, Any]] = {}

    def evaluate(self, findings: list[Finding]) -> dict[str, Any]:
        """Evaluate findings against this framework's controls.

        Args:
            findings: All findings from the scan.

        Returns:
            Dict with ``score``, ``passed``, ``failed``, ``gaps``, and ``control_results``.
        """
        control_results: dict[str, dict[str, Any]] = {}

        for ctrl_id, ctrl_meta in self.controls.items():
            # Find findings that reference this control
            related = [
                f for f in findings
                if ctrl_id in f.compliance_tags
            ]

            failing = [f for f in related if f.status == "fail"]
            warnings = [f for f in related if f.status == "warning"]

            if not related:
                status = "not_tested"
            elif failing:
                status = "fail"
            elif warnings:
                status = "warning"
            else:
                status = "pass"

            control_results[ctrl_id] = {
                "title": ctrl_meta.get("title", ctrl_id),
                "status": status,
                "finding_count": len(related),
                "failing_findings": [f.title for f in failing],
                "remediation": ctrl_meta.get("remediation", ""),
            }

        # Calculate score: (passed + not_tested * 0.5) / total * 100
        total = len(self.controls)
        if total == 0:
            score = 100
        else:
            pass_count = sum(1 for r in control_results.values() if r["status"] == "pass")
            not_tested = sum(1 for r in control_results.values() if r["status"] == "not_tested")
            score = int((pass_count + not_tested * 0.5) / total * 100)

        gaps = [
            {"control": cid, "title": cr["title"], "remediation": cr["remediation"]}
            for cid, cr in control_results.items()
            if cr["status"] == "fail"
        ]

        return {
            "framework": self.name,
            "description": self.description,
            "score": score,
            "total_controls": total,
            "passed": sum(1 for r in control_results.values() if r["status"] == "pass"),
            "failed": sum(1 for r in control_results.values() if r["status"] == "fail"),
            "warnings": sum(1 for r in control_results.values() if r["status"] == "warning"),
            "not_tested": sum(1 for r in control_results.values() if r["status"] == "not_tested"),
            "gaps": gaps,
            "control_results": control_results,
        }
