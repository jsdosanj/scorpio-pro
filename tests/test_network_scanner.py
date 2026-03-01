"""Tests for NetworkScanner."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

from scorpio_pro.scanners.network_scanner import NetworkScanner
from scorpio_pro.config.scope import ScopeConfig


@pytest.fixture
def scanner() -> NetworkScanner:
    return NetworkScanner()


@pytest.fixture
def scope() -> ScopeConfig:
    return ScopeConfig(ips=["127.0.0.1"], engagement_name="Network Test")


@pytest.fixture
def empty_scope() -> ScopeConfig:
    return ScopeConfig(engagement_name="Empty Scope")


class TestNetworkScannerPrerequisites:
    def test_prerequisites_returns_bool(self, scanner: NetworkScanner) -> None:
        result = scanner.check_prerequisites()
        assert isinstance(result, bool)

    def test_prerequisites_true_without_nmap(self, scanner: NetworkScanner) -> None:
        with patch("scorpio_pro.scanners.network_scanner._NMAP_AVAILABLE", False):
            with patch("subprocess.run", side_effect=FileNotFoundError):
                assert scanner.check_prerequisites() is True


class TestNetworkScannerRun:
    def test_run_returns_list(self, scanner: NetworkScanner, scope: ScopeConfig) -> None:
        with patch.object(scanner, "_port_scan", return_value=[]):
            with patch.object(scanner, "_dns_enumeration", return_value=[]):
                with patch.object(scanner, "_check_dangerous_services", return_value=[]):
                    findings = scanner.run(scope)
        assert isinstance(findings, list)

    def test_run_with_empty_scope_uses_localhost(
        self, scanner: NetworkScanner, empty_scope: ScopeConfig
    ) -> None:
        with patch.object(scanner, "_port_scan", return_value=[]) as mock_ps:
            with patch.object(scanner, "_dns_enumeration", return_value=[]):
                with patch.object(scanner, "_check_dangerous_services", return_value=[]):
                    scanner.run(empty_scope)
        mock_ps.assert_called_once()


class TestDNSEnumeration:
    def test_dns_enumeration_returns_findings(
        self, scanner: NetworkScanner, scope: ScopeConfig
    ) -> None:
        findings = scanner._dns_enumeration(scope)
        assert isinstance(findings, list)
        assert len(findings) >= 1
        assert findings[0].test_run == "dns_enumeration"

    def test_dns_enumeration_handles_resolution_failure(
        self, scanner: NetworkScanner
    ) -> None:
        scope = ScopeConfig(applications=["nonexistent.invalid.domain.xyz"])
        findings = scanner._dns_enumeration(scope)
        assert "DNS resolution failed" in findings[0].evidence


class TestFallbackTCPScan:
    def test_tcp_connect_returns_false_on_closed_port(self, scanner: NetworkScanner) -> None:
        result = scanner._tcp_connect("127.0.0.1", 19999)  # unlikely to be open
        assert isinstance(result, bool)

    def test_fallback_scan_returns_findings(
        self, scanner: NetworkScanner, scope: ScopeConfig
    ) -> None:
        with patch.object(scanner, "_tcp_connect") as mock_conn:
            mock_conn.side_effect = lambda h, p, **kw: p == 22
            findings = scanner._fallback_tcp_scan(["127.0.0.1"], scope)
        assert isinstance(findings, list)


class TestDangerousServiceCheck:
    def test_no_dangerous_services_returns_empty(self, scanner: NetworkScanner) -> None:
        findings_with_safe_ports = [
            MagicMock(metadata={"host": "1.2.3.4", "open_ports": [{"port": 443}]})
        ]
        result = scanner._check_dangerous_services(findings_with_safe_ports)
        assert result == []

    def test_telnet_flagged_as_dangerous(self, scanner: NetworkScanner) -> None:
        findings_with_telnet = [
            MagicMock(metadata={"host": "1.2.3.4", "open_ports": [{"port": 23}]})
        ]
        result = scanner._check_dangerous_services(findings_with_telnet)
        assert len(result) == 1
        assert result[0].severity == "High"

    def test_ftp_flagged_as_dangerous(self, scanner: NetworkScanner) -> None:
        findings_with_ftp = [
            MagicMock(metadata={"host": "1.2.3.4", "open_ports": [{"port": 21}]})
        ]
        result = scanner._check_dangerous_services(findings_with_ftp)
        assert len(result) == 1

    def test_dangerous_finding_has_compliance_tags(self, scanner: NetworkScanner) -> None:
        findings_with_telnet = [
            MagicMock(metadata={"host": "1.2.3.4", "open_ports": [{"port": 23}]})
        ]
        result = scanner._check_dangerous_services(findings_with_telnet)
        assert len(result[0].compliance_tags) > 0


class TestExtractHostname:
    """Test the _extract_hostname static method on VulnScanner."""

    def test_strips_https(self) -> None:
        from scorpio_pro.scanners.vuln_scanner import VulnScanner
        assert VulnScanner._extract_hostname("https://example.com/path") == "example.com"

    def test_strips_http(self) -> None:
        from scorpio_pro.scanners.vuln_scanner import VulnScanner
        assert VulnScanner._extract_hostname("http://example.com") == "example.com"

    def test_bare_hostname(self) -> None:
        from scorpio_pro.scanners.vuln_scanner import VulnScanner
        assert VulnScanner._extract_hostname("example.com") == "example.com"
