"""Remote access scanner — SSH, RDP, and VPN configuration analysis."""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

try:
    import paramiko
    _PARAMIKO_AVAILABLE = True
except ImportError:
    _PARAMIKO_AVAILABLE = False


class RemoteAccessScanner(BaseScanner):
    """Audits remote access services for security misconfigurations.

    Covers:
    - SSH: protocol version, weak algorithms, root login, password auth
    - RDP: NLA enforcement, encryption level, BlueKeep indicator
    - VPN: OpenVPN/WireGuard/IPSec config file audits
    """

    name = "Remote Access Scanner"
    description = "SSH, RDP, and VPN configuration security analysis."

    def check_prerequisites(self) -> bool:
        """Check that paramiko is available for SSH analysis."""
        if not _PARAMIKO_AVAILABLE:
            self._log.warning(
                "paramiko not installed; SSH crypto analysis will be limited."
            )
        return True

    def run(self, scope: Any) -> list[Finding]:
        """Execute remote access security checks.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of remote access findings.
        """
        findings: list[Finding] = []
        targets = scope.all_targets()
        if not targets:
            targets = [socket.gethostbyname(socket.gethostname())]

        for ip in targets[:20]:
            if self._port_open(ip, 22):
                findings.extend(self._check_ssh(ip))
            if self._port_open(ip, 3389):
                findings.extend(self._check_rdp(ip))

        findings.extend(self._audit_vpn_configs())
        findings.extend(self._check_local_ssh_config())

        return findings

    # ------------------------------------------------------------------ #
    # SSH Analysis                                                         #
    # ------------------------------------------------------------------ #

    def _check_ssh(self, host: str) -> list[Finding]:
        """Analyse SSH server configuration on *host*."""
        issues: list[str] = []
        info: dict[str, Any] = {"host": host}

        if _PARAMIKO_AVAILABLE:
            try:
                transport = paramiko.Transport((host, 22))
                transport.start_client(timeout=10)
                server_key = transport.get_remote_server_key()
                info["host_key_type"] = server_key.get_name()
                info["host_key_bits"] = getattr(server_key, "get_bits", lambda: "N/A")()
                info["server_version"] = transport.remote_version
                security_options = transport.get_security_options()
                info["kex"] = list(security_options.kex)
                info["ciphers"] = list(security_options.ciphers)
                info["digests"] = list(security_options.digests)
                transport.close()

                # Flag SSH v1 or old version strings
                if "SSH-1" in info.get("server_version", ""):
                    issues.append("SSH protocol version 1 detected.")

                # Weak key exchange algorithms
                weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
                for kex in info.get("kex", []):
                    if kex in weak_kex:
                        issues.append(f"Weak KEX algorithm: {kex}")

                # Weak ciphers
                weak_ciphers = {"arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc"}
                for cipher in info.get("ciphers", []):
                    if cipher in weak_ciphers:
                        issues.append(f"Weak cipher: {cipher}")

                # Weak MAC
                weak_macs = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96"}
                for mac in info.get("digests", []):
                    if mac in weak_macs:
                        issues.append(f"Weak MAC algorithm: {mac}")

                # Small RSA key
                if (
                    info.get("host_key_type") == "ssh-rsa"
                    and isinstance(info.get("host_key_bits"), int)
                    and info["host_key_bits"] < 2048
                ):
                    issues.append(
                        f"RSA host key too small: {info['host_key_bits']} bits (minimum 2048)."
                    )

            except Exception as exc:
                self._log.debug("SSH analysis error on %s: %s", host, exc)
                info["error"] = str(exc)

        # Try to read sshd_config if scanning localhost
        local_issues = self._check_sshd_config()
        issues.extend(local_issues)

        severity = "High" if issues else "Informational"
        status = "fail" if issues else "pass"

        return [
            Finding(
                title=f"SSH Configuration: {host}",
                severity=severity,
                description=(
                    f"{len(issues)} SSH issue(s) detected on {host}."
                    if issues
                    else f"SSH configuration appears secure on {host}."
                ),
                evidence=json.dumps({"issues": issues, "info": info}, indent=2),
                remediation=(
                    "Disable SSH v1. Remove weak KEX, ciphers, and MAC algorithms. "
                    "Enforce RSA key size ≥ 2048 bits. Disable root login. "
                    "Disable password authentication; use key-based auth only."
                ),
                test_run="ssh_analysis",
                rationale="SSH misconfigurations enable MITM attacks and brute-force exploitation.",
                methodology="Connected via paramiko Transport; inspected negotiated algorithms.",
                status=status,
                compliance_tags=[
                    "NIST-PR.AC-3", "HIPAA-164.312(e)(1)", "GDPR-Art32",
                ],
                metadata=info,
            )
        ]

    def _check_sshd_config(self) -> list[str]:
        """Parse local /etc/ssh/sshd_config for insecure settings."""
        issues: list[str] = []
        config_path = Path("/etc/ssh/sshd_config")
        if not config_path.exists():
            return issues

        try:
            content = config_path.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            return issues

        checks = {
            "PermitRootLogin yes": "Root SSH login is permitted.",
            "PasswordAuthentication yes": "Password authentication enabled (prefer key-based).",
            "PermitEmptyPasswords yes": "Empty passwords allowed for SSH.",
            "Protocol 1": "SSH Protocol 1 enabled.",
            "X11Forwarding yes": "X11 forwarding enabled (potential security risk).",
        }
        for directive, issue in checks.items():
            key, _, value = directive.partition(" ")
            for line in content.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith("#"):
                    continue
                if line_stripped.lower().startswith(key.lower()):
                    actual_value = line_stripped.split(None, 1)[1].lower().strip() if len(line_stripped.split(None, 1)) > 1 else ""
                    if actual_value == value.lower():
                        issues.append(issue)
        return issues

    # ------------------------------------------------------------------ #
    # RDP Analysis                                                         #
    # ------------------------------------------------------------------ #

    def _check_rdp(self, host: str) -> list[Finding]:
        """Check RDP port exposure and basic security indicators."""
        issues: list[str] = []
        info: dict[str, Any] = {"host": host, "port": 3389}

        # Check if NLA is enforced by probing the RDP handshake
        try:
            with socket.create_connection((host, 3389), timeout=5) as s:
                # Send RDP Connection Request PDU
                rdp_neg_req = bytes([
                    0x03, 0x00, 0x00, 0x13,  # TPKT header
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,  # X.224 CR
                    0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,  # RDP Neg Req
                ])
                s.sendall(rdp_neg_req)
                response = s.recv(64)
                if len(response) >= 19:
                    # Check security protocol in response
                    proto_byte = response[15] if len(response) > 15 else 0
                    if proto_byte & 0x02:
                        info["nla_supported"] = True
                    else:
                        info["nla_supported"] = False
                        issues.append("NLA (Network Level Authentication) not enforced on RDP.")
                    if proto_byte & 0x01:
                        info["ssl_supported"] = True
                else:
                    issues.append("Could not parse RDP negotiation response.")
        except Exception as exc:
            info["probe_error"] = str(exc)

        # BlueKeep (CVE-2019-0708) indicator — port open + old OS
        import platform as _platform
        if _platform.system() == "Windows":
            win_ver = _platform.version()
            try:
                major = int(win_ver.split(".")[0])
                if major < 10:
                    issues.append(
                        "Windows version may be vulnerable to BlueKeep (CVE-2019-0708). "
                        "Patch immediately or disable RDP."
                    )
            except ValueError:
                pass

        if not info.get("nla_supported") and not issues:
            issues.append("NLA status unknown — verify RDP is configured to require NLA.")

        severity = "Critical" if any("BlueKeep" in i for i in issues) else (
            "High" if issues else "Informational"
        )

        return [
            Finding(
                title=f"RDP Configuration: {host}",
                severity=severity,
                description=(
                    f"{len(issues)} RDP issue(s) on {host}."
                    if issues
                    else f"RDP basic checks passed on {host}."
                ),
                evidence=json.dumps({"issues": issues, "info": info}, indent=2),
                remediation=(
                    "Enable NLA for all RDP connections. "
                    "Apply all Windows security patches (especially MS19-0708). "
                    "Restrict RDP access via VPN or firewall allowlist. "
                    "Enable RDP logging and account lockout."
                ),
                test_run="rdp_analysis",
                rationale="RDP is one of the most commonly exploited remote access vectors.",
                methodology="Sent RDP Connection Request PDU and analysed Security Protocol flags.",
                status="fail" if issues else "pass",
                compliance_tags=[
                    "NIST-PR.AC-3", "HIPAA-164.312(a)(2)(iv)", "NIST-CSF-PR.PT-3",
                ],
                metadata=info,
            )
        ]

    # ------------------------------------------------------------------ #
    # VPN Config Audit                                                     #
    # ------------------------------------------------------------------ #

    def _audit_vpn_configs(self) -> list[Finding]:
        """Scan common locations for VPN config files and audit them."""
        findings: list[Finding] = []
        search_paths = [
            Path("/etc/openvpn"),
            Path("/etc/wireguard"),
            Path("/etc/ipsec.conf"),
            Path("/etc/strongswan.conf"),
            Path(os.path.expanduser("~/.config/openvpn")),
            Path(os.path.expanduser("~/Library/Application Support/Tunnelblick")),
        ]

        ovpn_issues: list[str] = []
        configs_found: list[str] = []

        for path in search_paths:
            if path.is_dir():
                for config_file in path.rglob("*.conf"):
                    configs_found.append(str(config_file))
                    ovpn_issues.extend(self._audit_openvpn_file(config_file))
                for config_file in path.rglob("*.ovpn"):
                    configs_found.append(str(config_file))
                    ovpn_issues.extend(self._audit_openvpn_file(config_file))
            elif path.is_file():
                configs_found.append(str(path))
                ovpn_issues.extend(self._audit_openvpn_file(path))

        if not configs_found:
            return []

        return [
            Finding(
                title="VPN Configuration Audit",
                severity="High" if ovpn_issues else "Informational",
                description=(
                    f"{len(ovpn_issues)} VPN configuration issue(s) found."
                    if ovpn_issues
                    else f"No issues found in {len(configs_found)} VPN config file(s)."
                ),
                evidence=(
                    f"Configs found: {configs_found}\n"
                    "Issues:\n" + "\n".join(f"  - {i}" for i in ovpn_issues)
                ),
                remediation=(
                    "Use TLS 1.2+, strong cipher suites (AES-256-GCM), and SHA-256+ HMAC. "
                    "Enable tls-auth or tls-crypt. Disable weak protocols."
                ),
                test_run="vpn_config_audit",
                rationale="VPN misconfigurations can expose tunnels to interception or credential theft.",
                methodology="Parsed VPN config files in standard system locations.",
                status="fail" if ovpn_issues else "pass",
                compliance_tags=[
                    "HIPAA-164.312(e)(1)", "NIST-PR.AC-3", "GDPR-Art32",
                ],
                metadata={"configs_found": configs_found, "issues": ovpn_issues},
            )
        ]

    def _audit_openvpn_file(self, path: Path) -> list[str]:
        """Scan a single OpenVPN config for weak settings."""
        issues: list[str] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            return issues

        weak_checks = {
            "cipher des": "Weak cipher DES in use.",
            "cipher rc2": "Weak cipher RC2 in use.",
            "auth md5": "Weak MD5 HMAC authentication.",
            "tls-version-min 1.0": "TLS minimum version set to 1.0.",
            "comp-lzo": "LZO compression enabled — consider VORACLE attack.",
        }
        for pattern, issue in weak_checks.items():
            if pattern in content:
                issues.append(f"{path.name}: {issue}")

        if "tls-auth" not in content and "tls-crypt" not in content:
            issues.append(f"{path.name}: tls-auth/tls-crypt not configured.")

        return issues

    # ------------------------------------------------------------------ #
    # Local SSH client config                                              #
    # ------------------------------------------------------------------ #

    def _check_local_ssh_config(self) -> list[Finding]:
        """Check the current user's ~/.ssh/ directory for insecure permissions."""
        issues: list[str] = []
        ssh_dir = Path(os.path.expanduser("~/.ssh"))
        if not ssh_dir.exists():
            return []

        # Check directory permissions
        dir_mode = oct(ssh_dir.stat().st_mode)[-3:]
        if dir_mode not in ("700", "600"):
            issues.append(f"~/.ssh/ permissions are {dir_mode} (should be 700).")

        # Check private key permissions
        for key_file in ssh_dir.glob("id_*"):
            if key_file.suffix not in (".pub", ".cert"):
                mode = oct(key_file.stat().st_mode)[-3:]
                if mode not in ("600", "400"):
                    issues.append(f"{key_file.name} permissions are {mode} (should be 600).")

        # Check authorized_keys
        auth_keys = ssh_dir / "authorized_keys"
        if auth_keys.exists():
            mode = oct(auth_keys.stat().st_mode)[-3:]
            if mode not in ("600", "400"):
                issues.append(f"authorized_keys permissions are {mode} (should be 600).")

        return [
            Finding(
                title="SSH Client Configuration Security",
                severity="Medium" if issues else "Informational",
                description=(
                    f"{len(issues)} SSH client configuration issue(s) found."
                    if issues
                    else "SSH client configuration looks secure."
                ),
                evidence="\n".join(issues) if issues else "~/.ssh permissions OK.",
                remediation="Set ~/.ssh permissions to 700 and private key files to 600.",
                test_run="ssh_client_config",
                rationale="Insecure SSH key permissions allow other local users to steal private keys.",
                methodology="Checked filesystem permissions on ~/.ssh/ and its contents.",
                status="fail" if issues else "pass",
                compliance_tags=["NIST-PR.AC-1", "NIST-PR.DS-1"],
                metadata={"ssh_dir": str(ssh_dir), "issues": issues},
            )
        ]

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if TCP connection to host:port succeeds."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
