"""Tests for SystemScanner."""

from __future__ import annotations

import platform
from unittest.mock import MagicMock, patch

import pytest

from scorpio_pro.scanners.system_scanner import SystemScanner
from scorpio_pro.config.scope import ScopeConfig


@pytest.fixture
def scanner() -> SystemScanner:
    return SystemScanner()


@pytest.fixture
def scope() -> ScopeConfig:
    return ScopeConfig(ips=["127.0.0.1"], engagement_name="Test")


class TestSystemScannerPrerequisites:
    def test_check_prerequisites_returns_bool(self, scanner: SystemScanner) -> None:
        result = scanner.check_prerequisites()
        assert isinstance(result, bool)

    def test_check_prerequisites_always_true(self, scanner: SystemScanner) -> None:
        assert scanner.check_prerequisites() is True


class TestSystemScannerRun:
    def test_run_returns_list(self, scanner: SystemScanner, scope: ScopeConfig) -> None:
        findings = scanner.run(scope)
        assert isinstance(findings, list)

    def test_findings_have_required_fields(self, scanner: SystemScanner, scope: ScopeConfig) -> None:
        findings = scanner.run(scope)
        for finding in findings:
            assert finding.title
            assert finding.severity in {"Critical", "High", "Medium", "Low", "Informational"}
            assert finding.status in {"pass", "fail", "warning"}
            assert finding.test_run

    def test_run_produces_host_info_finding(self, scanner: SystemScanner, scope: ScopeConfig) -> None:
        findings = scanner.run(scope)
        test_names = [f.test_run for f in findings]
        assert "system_info" in test_names

    def test_run_produces_firewall_finding(self, scanner: SystemScanner, scope: ScopeConfig) -> None:
        findings = scanner.run(scope)
        test_names = [f.test_run for f in findings]
        assert "firewall_status" in test_names

    def test_run_produces_disk_encryption_finding(self, scanner: SystemScanner, scope: ScopeConfig) -> None:
        findings = scanner.run(scope)
        test_names = [f.test_run for f in findings]
        assert "disk_encryption" in test_names


class TestHostInfoCollection:
    def test_collect_host_info_returns_finding(self, scanner: SystemScanner) -> None:
        findings = scanner._collect_host_info()
        assert len(findings) == 1
        assert findings[0].test_run == "system_info"
        assert findings[0].severity == "Informational"

    def test_host_info_contains_hostname(self, scanner: SystemScanner) -> None:
        import socket
        findings = scanner._collect_host_info()
        assert socket.gethostname() in findings[0].evidence

    def test_host_info_metadata_has_hostname(self, scanner: SystemScanner) -> None:
        import socket
        findings = scanner._collect_host_info()
        assert findings[0].metadata["hostname"] == socket.gethostname()


class TestFirewallCheck:
    def test_firewall_check_returns_finding(self, scanner: SystemScanner) -> None:
        findings = scanner._check_firewall()
        assert len(findings) == 1
        assert findings[0].test_run == "firewall_status"

    def test_firewall_finding_has_compliance_tags(self, scanner: SystemScanner) -> None:
        findings = scanner._check_firewall()
        assert len(findings[0].compliance_tags) > 0


class TestDiskEncryptionCheck:
    def test_disk_encryption_returns_finding(self, scanner: SystemScanner) -> None:
        findings = scanner._check_disk_encryption()
        assert len(findings) == 1
        assert findings[0].test_run == "disk_encryption"

    def test_disk_encryption_severity_when_disabled(self, scanner: SystemScanner) -> None:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="FileVault is Off.", returncode=0)
            with patch("platform.system", return_value="Darwin"):
                findings = scanner._check_disk_encryption()
        assert findings[0].severity in {"High", "Informational"}


class TestUserAccountCheck:
    def test_user_accounts_returns_findings(self, scanner: SystemScanner) -> None:
        findings = scanner._check_user_accounts()
        assert len(findings) >= 1

    def test_user_accounts_compliance_tags(self, scanner: SystemScanner) -> None:
        findings = scanner._check_user_accounts()
        assert "HIPAA-164.312(a)(2)(i)" in findings[0].compliance_tags


class TestRunningServicesCheck:
    def test_running_services_returns_findings(self, scanner: SystemScanner) -> None:
        findings = scanner._check_running_services()
        assert len(findings) == 1

    def test_no_risky_services_status_pass(self, scanner: SystemScanner) -> None:
        with patch("scorpio_pro.scanners.system_scanner._PSUTIL_AVAILABLE", True):
            with patch("psutil.process_iter", return_value=[]):
                with patch("platform.system", return_value="Windows"):
                    findings = scanner._check_running_services()
        assert findings[0].status == "pass"
