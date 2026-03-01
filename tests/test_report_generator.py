"""Tests for ReportGenerator and formatters."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scorpio_pro.scanners.base_scanner import Finding
from scorpio_pro.config.scope import ScopeConfig
from scorpio_pro.reporting.report_generator import ReportGenerator


def _make_finding(severity: str = "High", status: str = "fail") -> Finding:
    return Finding(
        title=f"Test Finding — {severity}",
        severity=severity,
        description="A test finding.",
        evidence="Evidence data.",
        remediation="Fix it.",
        test_run="test_check",
        rationale="Important for security.",
        methodology="Automated check.",
        status=status,
        compliance_tags=["HIPAA-164.312(a)(2)(iv)", "GDPR-Art32"],
    )


def _make_scope() -> ScopeConfig:
    return ScopeConfig(
        ips=["192.168.1.1"],
        engagement_name="Unit Test Engagement",
        authorised_by="Test Tester",
    )


def _sample_compliance() -> dict[str, Any]:
    return {
        "HIPAA": {
            "framework": "HIPAA",
            "score": 60,
            "passed": 6,
            "failed": 4,
            "warnings": 0,
            "not_tested": 2,
            "total_controls": 12,
            "gaps": [
                {"control": "HIPAA-164.312(a)(2)(iv)", "title": "Encryption", "remediation": "Enable encryption."}
            ],
            "control_results": {},
            "description": "HIPAA Security Rule.",
        },
        "GDPR": {
            "framework": "GDPR",
            "score": 70,
            "passed": 7,
            "failed": 3,
            "warnings": 0,
            "not_tested": 1,
            "total_controls": 11,
            "gaps": [],
            "control_results": {},
            "description": "GDPR.",
        },
    }


# ── ReportGenerator ────────────────────────────────────────────────────────────

class TestReportGenerator:
    def test_generate_creates_files(self, tmp_path: Path) -> None:
        findings = [_make_finding()]
        gen = ReportGenerator(
            findings=findings,
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["txt", "json"])
        assert len(paths) == 2
        for p in paths:
            assert p.exists()

    def test_generate_json_is_valid(self, tmp_path: Path) -> None:
        findings = [_make_finding()]
        gen = ReportGenerator(
            findings=findings,
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["json"])
        json_path = paths[0]
        data = json.loads(json_path.read_text())
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_generate_txt_contains_title(self, tmp_path: Path) -> None:
        finding = _make_finding(severity="Critical")
        gen = ReportGenerator(
            findings=[finding],
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["txt"])
        content = paths[0].read_text()
        assert "SCORPIO PRO" in content
        assert finding.title in content

    def test_generate_html_contains_engagement_name(self, tmp_path: Path) -> None:
        scope = _make_scope()
        gen = ReportGenerator(
            findings=[_make_finding()],
            compliance_results=_sample_compliance(),
            scope=scope,
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["html"])
        content = paths[0].read_text()
        assert scope.engagement_name in content

    def test_generate_unknown_format_skipped(self, tmp_path: Path) -> None:
        gen = ReportGenerator(
            findings=[],
            compliance_results={},
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["unknown_format"])
        assert paths == []

    def test_generate_empty_findings(self, tmp_path: Path) -> None:
        gen = ReportGenerator(
            findings=[],
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["json", "txt"])
        assert len(paths) == 2

    def test_json_report_has_compliance(self, tmp_path: Path) -> None:
        gen = ReportGenerator(
            findings=[],
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["json"])
        data = json.loads(paths[0].read_text())
        assert "HIPAA" in data["compliance"]

    def test_txt_report_has_compliance_scorecard(self, tmp_path: Path) -> None:
        gen = ReportGenerator(
            findings=[],
            compliance_results=_sample_compliance(),
            scope=_make_scope(),
            output_dir=tmp_path,
        )
        paths = gen.generate(formats=["txt"])
        content = paths[0].read_text()
        assert "COMPLIANCE SCORECARD" in content


# ── Finding serialization ──────────────────────────────────────────────────────

class TestFindingSerialization:
    def test_to_dict_returns_dict(self) -> None:
        finding = _make_finding()
        d = finding.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_has_all_keys(self) -> None:
        finding = _make_finding()
        d = finding.to_dict()
        for key in (
            "title", "severity", "description", "evidence",
            "remediation", "test_run", "rationale", "methodology",
            "status", "compliance_tags", "metadata",
        ):
            assert key in d

    def test_severity_score_ordering(self) -> None:
        critical = _make_finding(severity="Critical")
        low = _make_finding(severity="Low")
        assert critical.severity_score() > low.severity_score()
