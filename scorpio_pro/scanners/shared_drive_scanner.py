"""Shared drive scanner — SMB/CIFS, NFS, and AFP share enumeration."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding


class SharedDriveScanner(BaseScanner):
    """Enumerates and audits network file shares for permission issues.

    Capabilities:
    - SMB/CIFS share enumeration via smbclient/net
    - NFS export enumeration via showmount
    - AFP share detection
    - Permission auditing (anonymous/guest access)
    - Sensitive data exposure indicators
    """

    name = "Shared Drive Scanner"
    description = "SMB, NFS, and AFP share enumeration and permission auditing."

    def check_prerequisites(self) -> bool:
        """Check that smbclient or showmount are available."""
        has_smb = self._command_available("smbclient")
        has_nfs = self._command_available("showmount")
        if not has_smb and not has_nfs:
            self._log.warning(
                "Neither smbclient nor showmount found; shared drive scan will be limited."
            )
        return True  # graceful degradation

    def run(self, scope: Any) -> list[Finding]:
        """Execute shared drive enumeration checks.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of shared drive findings.
        """
        findings: list[Finding] = []
        targets = scope.all_targets()
        if not targets:
            targets = [socket.gethostbyname(socket.gethostname())]

        for ip in targets[:20]:
            if self._port_open(ip, 445) or self._port_open(ip, 139):
                findings.extend(self._scan_smb(ip))
            if self._port_open(ip, 2049):
                findings.extend(self._scan_nfs(ip))
            if self._port_open(ip, 548):
                findings.extend(self._scan_afp(ip))

        findings.extend(self._check_local_shares())

        return findings

    # ------------------------------------------------------------------ #
    # SMB / CIFS                                                           #
    # ------------------------------------------------------------------ #

    def _scan_smb(self, host: str) -> list[Finding]:
        """Enumerate SMB shares and check for anonymous access."""
        shares: list[str] = []
        anonymous_shares: list[str] = []
        errors: list[str] = []

        # Try null session enumeration
        if self._command_available("smbclient"):
            try:
                result = subprocess.run(
                    ["smbclient", "-L", host, "-N", "--no-pass"],
                    capture_output=True, text=True, timeout=15,
                )
                output = result.stdout + result.stderr
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("Disk") or "\tDisk" in line or "IPC" in line:
                        parts = line.split()
                        if parts:
                            shares.append(parts[0])
                if "NT_STATUS_ACCESS_DENIED" not in output:
                    # Null session succeeded — flag all shares as anonymous-accessible
                    anonymous_shares = list(shares)
            except Exception as exc:
                errors.append(str(exc))

        # Try via net (Linux)
        if not shares and self._command_available("net"):
            try:
                result = subprocess.run(
                    ["net", "view", host],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    if "Disk" in line:
                        shares.append(line.split()[0])
            except Exception as exc:
                errors.append(str(exc))

        severity = "Critical" if anonymous_shares else ("Medium" if shares else "Informational")
        status = "fail" if anonymous_shares else ("warning" if shares else "pass")

        return [
            Finding(
                title=f"SMB Share Enumeration: {host}",
                severity=severity,
                description=(
                    f"Anonymous access to {len(anonymous_shares)} SMB share(s) on {host}."
                    if anonymous_shares
                    else (
                        f"{len(shares)} SMB share(s) found on {host} (authentication required)."
                        if shares
                        else f"No SMB shares accessible on {host}."
                    )
                ),
                evidence=(
                    f"Shares: {shares}\n"
                    f"Anonymous access: {anonymous_shares}\n"
                    f"Errors: {errors}"
                ),
                remediation=(
                    "Disable anonymous/null session SMB access. "
                    "Restrict SMB to authorised users only. "
                    "Disable SMBv1. Consider blocking SMB at the perimeter firewall."
                ),
                test_run="smb_enumeration",
                rationale="Anonymous SMB access enables data theft and lateral movement.",
                methodology="Ran smbclient with null session to enumerate shares.",
                status=status,
                compliance_tags=[
                    "NIST-PR.AC-3", "HIPAA-164.312(a)(1)", "GDPR-Art32",
                ],
                metadata={
                    "host": host,
                    "shares": shares,
                    "anonymous_shares": anonymous_shares,
                },
            )
        ]

    # ------------------------------------------------------------------ #
    # NFS                                                                  #
    # ------------------------------------------------------------------ #

    def _scan_nfs(self, host: str) -> list[Finding]:
        """Enumerate NFS exports and check for world-accessible mounts."""
        exports: list[str] = []
        world_readable: list[str] = []

        if self._command_available("showmount"):
            try:
                result = subprocess.run(
                    ["showmount", "-e", host],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    if line.startswith("/"):
                        exports.append(line.strip())
                        if "*(ro)" in line or "*(rw)" in line or " *" in line:
                            world_readable.append(line.strip())
            except Exception as exc:
                self._log.debug("showmount error for %s: %s", host, exc)

        if not exports:
            return []

        return [
            Finding(
                title=f"NFS Export Enumeration: {host}",
                severity="High" if world_readable else "Medium",
                description=(
                    f"{len(world_readable)} NFS export(s) accessible by everyone (*)."
                    if world_readable
                    else f"{len(exports)} NFS export(s) found (restricted access)."
                ),
                evidence="\n".join(exports),
                remediation=(
                    "Remove world-accessible NFS exports. "
                    "Restrict exports to specific hostnames or IP ranges. "
                    "Use Kerberos authentication for NFS."
                ),
                test_run="nfs_enumeration",
                rationale="World-accessible NFS exports allow any host to mount and read/write files.",
                methodology="Ran showmount -e to enumerate NFS exports.",
                status="fail" if world_readable else "warning",
                compliance_tags=[
                    "NIST-PR.AC-3", "HIPAA-164.312(a)(1)", "GDPR-Art32",
                ],
                metadata={
                    "host": host,
                    "exports": exports,
                    "world_readable": world_readable,
                },
            )
        ]

    # ------------------------------------------------------------------ #
    # AFP                                                                  #
    # ------------------------------------------------------------------ #

    def _scan_afp(self, host: str) -> list[Finding]:
        """Detect AFP (Apple Filing Protocol) service and flag it as legacy."""
        return [
            Finding(
                title=f"AFP Service Detected: {host}",
                severity="Medium",
                description=(
                    f"AFP (Apple Filing Protocol) is listening on {host}:548. "
                    "AFP is a legacy protocol deprecated since macOS 11."
                ),
                evidence=f"TCP port 548 open on {host}.",
                remediation=(
                    "Migrate file sharing to SMB 3.x. "
                    "Disable AFP service to reduce the attack surface."
                ),
                test_run="afp_detection",
                rationale="AFP is deprecated and lacks modern security features.",
                methodology="Detected open TCP port 548 on target host.",
                status="warning",
                compliance_tags=["NIST-PR.AC-5"],
                metadata={"host": host, "port": 548},
            )
        ]

    # ------------------------------------------------------------------ #
    # Local shares                                                         #
    # ------------------------------------------------------------------ #

    def _check_local_shares(self) -> list[Finding]:
        """Check locally configured file shares on this system."""
        import platform as _platform
        system = _platform.system()
        shares: list[str] = []
        issues: list[str] = []

        if system == "Linux":
            # Check /etc/exports (NFS)
            exports_file = Path("/etc/exports")
            if exports_file.exists():
                try:
                    content = exports_file.read_text(encoding="utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            shares.append(f"NFS: {line}")
                            if "*(ro)" in line or "*(rw)" in line or " *" in line:
                                issues.append(f"World-accessible NFS export: {line}")
                except PermissionError:
                    pass

            # Check Samba shares
            smb_conf = Path("/etc/samba/smb.conf")
            if smb_conf.exists():
                try:
                    content = smb_conf.read_text(encoding="utf-8", errors="ignore")
                    if "public = yes" in content.lower() or "guest ok = yes" in content.lower():
                        issues.append("Samba has public/guest shares configured.")
                    # Count share sections
                    share_count = content.count("[") - 1  # minus [global]
                    shares.append(f"Samba: ~{share_count} share(s) configured.")
                except PermissionError:
                    pass

        elif system == "Darwin":
            # Check if file sharing is enabled
            try:
                result = subprocess.run(
                    ["launchctl", "list", "com.apple.smbd"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    shares.append("macOS SMB file sharing service is running.")
            except Exception:
                pass

        if not shares and not issues:
            return []

        return [
            Finding(
                title="Local File Shares Configuration",
                severity="High" if issues else "Informational",
                description=(
                    f"{len(issues)} local share misconfiguration(s) found."
                    if issues
                    else f"{len(shares)} local share configuration(s) detected."
                ),
                evidence="\n".join(shares + issues),
                remediation=(
                    "Remove world-accessible share configurations. "
                    "Require authentication for all shares. "
                    "Limit share access to specific users/groups."
                ),
                test_run="local_shares",
                rationale="Misconfigured local shares can expose sensitive data.",
                methodology="Parsed /etc/exports and /etc/samba/smb.conf.",
                status="fail" if issues else "pass",
                compliance_tags=["NIST-PR.AC-3", "HIPAA-164.312(a)(1)", "GDPR-Art32"],
                metadata={"shares": shares, "issues": issues},
            )
        ]

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _command_available(cmd: str) -> bool:
        """Return True if *cmd* is available in PATH."""
        try:
            subprocess.run(
                [cmd, "--help"], capture_output=True, timeout=3
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if TCP connection to host:port succeeds."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
