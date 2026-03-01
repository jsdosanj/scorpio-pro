"""Tests for the compliance engine and framework evaluators."""

from __future__ import annotations

import pytest

from scorpio_pro.scanners.base_scanner import Finding
from scorpio_pro.compliance.engine import ComplianceEngine, BaseComplianceFramework
from scorpio_pro.compliance.hipaa import HIPAACompliance
from scorpio_pro.compliance.ferpa import FERPACompliance
from scorpio_pro.compliance.nist_csf import NISTCSFCompliance
from scorpio_pro.compliance.nist_ai import NISTAICompliance
from scorpio_pro.compliance.gdpr import GDPRCompliance


def _make_finding(
    title: str = "Test",
    severity: str = "Medium",
    status: str = "pass",
    compliance_tags: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        description="Test description.",
        evidence="Test evidence.",
        remediation="Test remediation.",
        test_run="test_run",
        rationale="Test rationale.",
        methodology="Test methodology.",
        status=status,
        compliance_tags=compliance_tags or [],
    )


class TestBaseComplianceFramework:
    class _ConcreteFramework(BaseComplianceFramework):
        name = "TestFW"
        controls = {
            "TEST-1": {
                "title": "Control 1",
                "description": "Desc 1",
                "remediation": "Fix 1",
            },
            "TEST-2": {
                "title": "Control 2",
                "description": "Desc 2",
                "remediation": "Fix 2",
            },
        }

    def test_evaluate_returns_dict(self) -> None:
        fw = self._ConcreteFramework()
        result = fw.evaluate([])
        assert isinstance(result, dict)

    def test_evaluate_required_keys(self) -> None:
        fw = self._ConcreteFramework()
        result = fw.evaluate([])
        for key in ("score", "passed", "failed", "gaps", "control_results", "total_controls"):
            assert key in result

    def test_score_is_int_in_range(self) -> None:
        fw = self._ConcreteFramework()
        result = fw.evaluate([])
        assert 0 <= result["score"] <= 100

    def test_failing_finding_reduces_score(self) -> None:
        fw = self._ConcreteFramework()
        passing = fw.evaluate([])
        failing_finding = _make_finding(status="fail", compliance_tags=["TEST-1"])
        failing = fw.evaluate([failing_finding])
        assert failing["score"] <= passing["score"]

    def test_failing_finding_appears_in_gaps(self) -> None:
        fw = self._ConcreteFramework()
        failing_finding = _make_finding(status="fail", compliance_tags=["TEST-1"])
        result = fw.evaluate([failing_finding])
        gap_controls = [g["control"] for g in result["gaps"]]
        assert "TEST-1" in gap_controls

    def test_passing_finding_not_in_gaps(self) -> None:
        fw = self._ConcreteFramework()
        passing_finding = _make_finding(status="pass", compliance_tags=["TEST-1"])
        result = fw.evaluate([passing_finding])
        gap_controls = [g["control"] for g in result["gaps"]]
        assert "TEST-1" not in gap_controls

    def test_not_tested_control_result(self) -> None:
        fw = self._ConcreteFramework()
        result = fw.evaluate([])  # no findings for TEST-1 or TEST-2
        for ctrl in result["control_results"].values():
            assert ctrl["status"] == "not_tested"


class TestHIPAACompliance:
    def test_has_controls(self) -> None:
        fw = HIPAACompliance()
        assert len(fw.controls) > 0

    def test_name(self) -> None:
        assert HIPAACompliance.name == "HIPAA"

    def test_disk_encryption_maps_to_hipaa(self) -> None:
        fw = HIPAACompliance()
        finding = _make_finding(
            status="fail",
            compliance_tags=["HIPAA-164.312(a)(2)(iv)"],
        )
        result = fw.evaluate([finding])
        ctrl = result["control_results"]["HIPAA-164.312(a)(2)(iv)"]
        assert ctrl["status"] == "fail"


class TestFERPACompliance:
    def test_has_controls(self) -> None:
        assert len(FERPACompliance.controls) > 0

    def test_name(self) -> None:
        assert FERPACompliance.name == "FERPA"


class TestNISTCSFCompliance:
    def test_has_controls(self) -> None:
        assert len(NISTCSFCompliance.controls) > 0

    def test_name(self) -> None:
        assert NISTCSFCompliance.name == "NIST CSF 2.0"

    def test_asset_management_control_exists(self) -> None:
        assert "NIST-ID.AM-1" in NISTCSFCompliance.controls


class TestNISTAICompliance:
    def test_has_controls(self) -> None:
        assert len(NISTAICompliance.controls) > 0

    def test_name(self) -> None:
        assert NISTAICompliance.name == "NIST AI RMF"


class TestGDPRCompliance:
    def test_has_controls(self) -> None:
        assert len(GDPRCompliance.controls) > 0

    def test_name(self) -> None:
        assert GDPRCompliance.name == "GDPR"

    def test_art32_exists(self) -> None:
        assert "GDPR-Art32" in GDPRCompliance.controls


class TestComplianceEngine:
    def test_evaluate_returns_all_frameworks(self) -> None:
        engine = ComplianceEngine()
        result = engine.evaluate([])
        assert "HIPAA" in result
        assert "GDPR" in result
        assert "NIST CSF 2.0" in result
        assert "FERPA" in result
        assert "NIST AI RMF" in result

    def test_evaluate_with_findings(self) -> None:
        engine = ComplianceEngine()
        findings = [
            _make_finding(
                status="fail",
                compliance_tags=["HIPAA-164.312(a)(2)(iv)", "GDPR-Art32"],
            )
        ]
        result = engine.evaluate(findings)
        assert result["HIPAA"]["failed"] >= 1
        assert result["GDPR"]["failed"] >= 1

    def test_empty_findings_no_failures(self) -> None:
        engine = ComplianceEngine()
        result = engine.evaluate([])
        for fw in result.values():
            assert fw["failed"] == 0
