"""System information scanner — collects host details and security posture."""

from __future__ import annotations

import os
import platform
import socket
import subprocess
import sys
from typing import Any

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class SystemScanner(BaseScanner):
    """Collects comprehensive system information and detects local security issues.

    Covers:
    - Hostname, IP addresses, MAC addresses
    - OS version, kernel, architecture
    - Running services and processes
    - User accounts and privilege levels
    - Firewall status
    - Disk encryption status
    - Installed security software
    - BIOS/UEFI information (where accessible)
    - Installed application inventory
    """

    name = "System Scanner"
    description = "Collects system information and checks local security posture."

    def check_prerequisites(self) -> bool:
        """Check that psutil is available."""
        if not _PSUTIL_AVAILABLE:
            self._log.warning("psutil not available; some system checks will be limited.")
        return True  # graceful degradation — can run with reduced functionality

    def run(self, scope: Any) -> list[Finding]:
        """Execute all system-level checks.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` (unused for local checks).

        Returns:
            List of :class:`~scorpio_pro.scanners.base_scanner.Finding` objects.
        """
        findings: list[Finding] = []

        findings.extend(self._collect_host_info())
        findings.extend(self._check_os_patching())
        findings.extend(self._check_user_accounts())
        findings.extend(self._check_firewall())
        findings.extend(self._check_disk_encryption())
        findings.extend(self._check_security_software())
        findings.extend(self._check_running_services())
        findings.extend(self._check_open_ports_local())

        return findings

    # ------------------------------------------------------------------ #
    # Host information                                                     #
    # ------------------------------------------------------------------ #

    def _collect_host_info(self) -> list[Finding]:
        """Gather hostname, IPs, MACs, OS details, and BIOS info."""
        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
        arch = platform.machine()
        python_ver = sys.version

        interfaces: dict[str, list[str]] = {}
        mac_addresses: dict[str, str] = {}

        if _PSUTIL_AVAILABLE:
            for iface, addrs in psutil.net_if_addrs().items():
                ips: list[str] = []
                for addr in addrs:
                    if addr.family == socket.AF_INET or addr.family == socket.AF_INET6:
                        ips.append(addr.address)
                    # AF_LINK / AF_PACKET — MAC
                    elif addr.family not in (socket.AF_INET, socket.AF_INET6):
                        if addr.address and addr.address != "00:00:00:00:00:00":
                            mac_addresses[iface] = addr.address
                if ips:
                    interfaces[iface] = ips
        else:
            try:
                interfaces["default"] = [socket.gethostbyname(hostname)]
            except Exception:
                interfaces["default"] = ["unknown"]

        evidence_lines = [
            f"Hostname      : {hostname}",
            f"OS            : {os_info}",
            f"Architecture  : {arch}",
            f"Python        : {python_ver}",
            "Interfaces    :",
        ]
        for iface, ips in interfaces.items():
            mac = mac_addresses.get(iface, "N/A")
            evidence_lines.append(f"  {iface}: {', '.join(ips)} (MAC: {mac})")

        bios = self._get_bios_info()
        if bios:
            evidence_lines.append(f"BIOS/UEFI     : {bios}")

        return [
            Finding(
                title="System Information Collected",
                severity="Informational",
                description="Basic host information was enumerated.",
                evidence="\n".join(evidence_lines),
                remediation="Review enumerated information for unintended exposure.",
                test_run="system_info",
                rationale="Asset inventory is the foundation of any security assessment.",
                methodology="Queried OS APIs via platform, socket, and psutil.",
                status="pass",
                compliance_tags=["NIST-ID.AM-1", "NIST-ID.AM-2"],
                metadata={
                    "hostname": hostname,
                    "os": os_info,
                    "arch": arch,
                    "interfaces": interfaces,
                    "mac_addresses": mac_addresses,
                },
            )
        ]

    def _get_bios_info(self) -> str:
        """Attempt to retrieve BIOS/UEFI information using OS-specific methods."""
        system = platform.system()
        try:
            if system == "Windows":
                result = subprocess.run(
                    ["wmic", "bios", "get", "Manufacturer,Name,Version"],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout.strip()
            elif system == "Linux":
                paths = [
                    "/sys/class/dmi/id/bios_vendor",
                    "/sys/class/dmi/id/bios_version",
                    "/sys/class/dmi/id/bios_date",
                ]
                parts = []
                for p in paths:
                    try:
                        parts.append(open(p).read().strip())
                    except Exception:
                        pass
                return " | ".join(parts) if parts else "N/A"
            elif system == "Darwin":
                result = subprocess.run(
                    ["system_profiler", "SPHardwareDataType"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    if "Boot ROM" in line or "SMC" in line:
                        return line.strip()
        except Exception:
            pass
        return "N/A"

    # ------------------------------------------------------------------ #
    # OS patching                                                          #
    # ------------------------------------------------------------------ #

    def _check_os_patching(self) -> list[Finding]:
        """Check whether the OS appears up-to-date."""
        system = platform.system()
        evidence = f"OS: {platform.system()} {platform.release()}"
        status = "warning"
        description = "Unable to automatically verify OS patch level on this platform."
        remediation = "Ensure automatic OS updates are enabled and the latest patches are applied."

        if system == "Linux":
            try:
                result = subprocess.run(
                    ["apt-get", "-s", "upgrade"], capture_output=True, text=True, timeout=30
                )
                if "0 upgraded" in result.stdout:
                    status = "pass"
                    description = "No pending APT upgrades detected."
                else:
                    status = "fail"
                    description = "Pending OS upgrades detected."
                evidence = result.stdout[:2000]
            except FileNotFoundError:
                try:
                    result = subprocess.run(
                        ["yum", "check-update"], capture_output=True, text=True, timeout=30
                    )
                    status = "pass" if result.returncode == 0 else "fail"
                    evidence = result.stdout[:2000]
                    description = "yum check-update completed."
                except FileNotFoundError:
                    pass
        elif system == "Darwin":
            try:
                result = subprocess.run(
                    ["softwareupdate", "-l"], capture_output=True, text=True, timeout=30
                )
                if "No new software available" in result.stdout:
                    status = "pass"
                    description = "No pending macOS software updates."
                else:
                    status = "fail"
                    description = "Pending macOS updates detected."
                evidence = result.stdout[:2000]
            except Exception:
                pass
        elif system == "Windows":
            description = "Windows Update status should be verified via Settings > Windows Update."

        return [
            Finding(
                title="OS Patch Level",
                severity="High" if status == "fail" else "Informational",
                description=description,
                evidence=evidence,
                remediation=remediation,
                test_run="os_patch_level",
                rationale="Unpatched systems are the most common attack vector.",
                methodology="Ran OS package manager dry-run upgrade check.",
                status=status,
                compliance_tags=[
                    "NIST-PR.IP-12", "HIPAA-164.308(a)(5)", "GDPR-Art32",
                    "NIST-CSF-PR.IP-12",
                ],
            )
        ]

    # ------------------------------------------------------------------ #
    # User accounts                                                        #
    # ------------------------------------------------------------------ #

    def _check_user_accounts(self) -> list[Finding]:
        """Enumerate user accounts and flag privileged accounts."""
        findings: list[Finding] = []
        system = platform.system()
        users: list[dict[str, Any]] = []

        if _PSUTIL_AVAILABLE:
            try:
                for user in psutil.users():
                    users.append({"name": user.name, "terminal": user.terminal, "host": user.host})
            except Exception:
                pass

        # Check for accounts with empty passwords (Linux)
        empty_password_users: list[str] = []
        if system == "Linux":
            try:
                with open("/etc/shadow") as fh:
                    for line in fh:
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1] == "":
                            empty_password_users.append(parts[0])
            except PermissionError:
                pass
            except Exception:
                pass

        evidence = f"Logged-in users: {users}\n"
        if empty_password_users:
            evidence += f"Accounts with empty/disabled passwords: {empty_password_users}"

        severity = "High" if empty_password_users else "Informational"
        status = "fail" if empty_password_users else "pass"

        findings.append(
            Finding(
                title="User Account Inventory",
                severity=severity,
                description=(
                    f"Found {len(users)} active user session(s). "
                    + (
                        f"{len(empty_password_users)} account(s) with empty/locked passwords."
                        if empty_password_users
                        else "No accounts with empty passwords detected."
                    )
                ),
                evidence=evidence,
                remediation=(
                    "Disable or remove accounts with empty passwords. "
                    "Enforce password/MFA policies for all interactive accounts."
                ),
                test_run="user_accounts",
                rationale="Excessive or misconfigured accounts increase the attack surface.",
                methodology="Enumerated active sessions via psutil; parsed /etc/shadow on Linux.",
                status=status,
                compliance_tags=[
                    "HIPAA-164.312(a)(2)(i)", "NIST-PR.AC-1", "GDPR-Art32", "FERPA-access",
                ],
                metadata={"users": users, "empty_password_users": empty_password_users},
            )
        )
        return findings

    # ------------------------------------------------------------------ #
    # Firewall                                                             #
    # ------------------------------------------------------------------ #

    def _check_firewall(self) -> list[Finding]:
        """Check whether the host firewall is enabled."""
        system = platform.system()
        enabled = False
        evidence = ""

        try:
            if system == "Linux":
                for cmd in [
                    ["ufw", "status"],
                    ["firewall-cmd", "--state"],
                    ["iptables", "-L", "-n"],
                ]:
                    try:
                        result = subprocess.run(
                            cmd, capture_output=True, text=True, timeout=10
                        )
                        if any(
                            kw in result.stdout.lower()
                            for kw in ("active", "running", "chain input")
                        ):
                            enabled = True
                            evidence = result.stdout[:1000]
                            break  # positive detection — no need to check further
                        elif not evidence:
                            # Record evidence from first command that ran, even if inactive
                            evidence = result.stdout[:1000]
                    except FileNotFoundError:
                        continue
            elif system == "Darwin":
                result = subprocess.run(
                    ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                    capture_output=True, text=True, timeout=10,
                )
                evidence = result.stdout.strip()
                enabled = "enabled" in evidence.lower()
            elif system == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True, text=True, timeout=10,
                )
                evidence = result.stdout[:1000]
                enabled = "ON" in result.stdout.upper()
        except Exception as exc:
            evidence = f"Could not determine firewall status: {exc}"

        return [
            Finding(
                title="Host Firewall Status",
                severity="High" if not enabled else "Informational",
                description=(
                    "Host firewall is ENABLED." if enabled else "Host firewall appears to be DISABLED or could not be verified."
                ),
                evidence=evidence or "No evidence collected.",
                remediation="Enable and configure the host firewall to restrict inbound/outbound traffic.",
                test_run="firewall_status",
                rationale="A host-based firewall provides an additional layer of defence-in-depth.",
                methodology=f"Queried OS-specific firewall management tools on {system}.",
                status="pass" if enabled else "fail",
                compliance_tags=[
                    "NIST-PR.AC-5", "HIPAA-164.312(e)(1)", "GDPR-Art32",
                ],
            )
        ]

    # ------------------------------------------------------------------ #
    # Disk encryption                                                      #
    # ------------------------------------------------------------------ #

    def _check_disk_encryption(self) -> list[Finding]:
        """Check whether full-disk encryption is active."""
        system = platform.system()
        encrypted = False
        evidence = ""

        try:
            if system == "Darwin":
                result = subprocess.run(
                    ["fdesetup", "status"], capture_output=True, text=True, timeout=10
                )
                evidence = result.stdout.strip()
                encrypted = "FileVault is On" in evidence
            elif system == "Linux":
                result = subprocess.run(
                    ["lsblk", "-o", "NAME,TYPE,MOUNTPOINT"],
                    capture_output=True, text=True, timeout=10,
                )
                evidence = result.stdout[:1000]
                encrypted = "crypt" in evidence.lower()
            elif system == "Windows":
                result = subprocess.run(
                    ["manage-bde", "-status"],
                    capture_output=True, text=True, timeout=10,
                )
                evidence = result.stdout[:1000]
                encrypted = "Protection On" in result.stdout
        except Exception as exc:
            evidence = f"Could not check disk encryption: {exc}"

        return [
            Finding(
                title="Full-Disk Encryption",
                severity="High" if not encrypted else "Informational",
                description=(
                    "Disk encryption is active." if encrypted
                    else "Disk encryption does not appear to be enabled."
                ),
                evidence=evidence or "No evidence collected.",
                remediation=(
                    "Enable full-disk encryption (FileVault on macOS, "
                    "BitLocker on Windows, LUKS on Linux)."
                ),
                test_run="disk_encryption",
                rationale="Encryption at rest protects data if physical access is obtained.",
                methodology=f"Queried OS-specific encryption tools on {system}.",
                status="pass" if encrypted else "fail",
                compliance_tags=[
                    "HIPAA-164.312(a)(2)(iv)", "NIST-PR.DS-1", "GDPR-Art32",
                ],
            )
        ]

    # ------------------------------------------------------------------ #
    # Security software                                                    #
    # ------------------------------------------------------------------ #

    def _check_security_software(self) -> list[Finding]:
        """Detect installed AV/EDR solutions."""
        system = platform.system()
        detected: list[str] = []

        av_names = [
            "CrowdStrike", "SentinelOne", "Carbon Black", "Defender",
            "ClamAV", "Sophos", "Symantec", "McAfee", "ESET", "Malwarebytes",
            "Trend Micro", "Kaspersky", "Cylance", "Palo Alto",
        ]

        if _PSUTIL_AVAILABLE:
            try:
                for proc in psutil.process_iter(["name", "exe"]):
                    pname = (proc.info.get("name") or "").lower()
                    pexe = (proc.info.get("exe") or "").lower()
                    for av in av_names:
                        if av.lower() in pname or av.lower() in pexe:
                            detected.append(f"{av} (process: {proc.info['name']})")
            except Exception:
                pass

        if system == "Darwin":
            try:
                result = subprocess.run(
                    ["system_profiler", "SPApplicationsDataType"],
                    capture_output=True, text=True, timeout=30,
                )
                for av in av_names:
                    if av.lower() in result.stdout.lower():
                        detected.append(f"{av} (installed application)")
            except Exception:
                pass

        detected = list(dict.fromkeys(detected))  # deduplicate

        return [
            Finding(
                title="Security Software Detection",
                severity="Medium" if not detected else "Informational",
                description=(
                    f"Detected security software: {', '.join(detected)}"
                    if detected
                    else "No antivirus or EDR software detected."
                ),
                evidence="\n".join(detected) if detected else "No security software processes found.",
                remediation=(
                    "Install and configure an endpoint security solution (EDR/AV)."
                    if not detected
                    else "Ensure security software is up to date and actively scanning."
                ),
                test_run="security_software",
                rationale="Endpoint security software detects and prevents malware execution.",
                methodology="Enumerated running processes and installed applications for known AV/EDR names.",
                status="pass" if detected else "warning",
                compliance_tags=["NIST-DE.CM-4", "HIPAA-164.308(a)(5)(ii)(B)"],
                metadata={"detected": detected},
            )
        ]

    # ------------------------------------------------------------------ #
    # Running services                                                     #
    # ------------------------------------------------------------------ #

    def _check_running_services(self) -> list[Finding]:
        """Enumerate running services and flag risky ones."""
        risky_services = {
            "telnet", "rsh", "rlogin", "rexec", "ftp", "tftp",
            "finger", "chargen", "daytime", "echo", "discard",
        }
        found_risky: list[str] = []
        services_list: list[str] = []

        if _PSUTIL_AVAILABLE:
            try:
                for proc in psutil.process_iter(["name", "status"]):
                    name = (proc.info.get("name") or "").lower()
                    services_list.append(name)
                    if name in risky_services:
                        found_risky.append(name)
            except Exception:
                pass

        system = platform.system()
        if system == "Linux":
            try:
                result = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"],
                    capture_output=True, text=True, timeout=15,
                )
                for line in result.stdout.splitlines():
                    for rs in risky_services:
                        if rs in line.lower():
                            found_risky.append(line.strip())
            except Exception:
                pass

        found_risky = list(dict.fromkeys(found_risky))

        return [
            Finding(
                title="Running Services Inventory",
                severity="High" if found_risky else "Informational",
                description=(
                    f"Risky services detected: {', '.join(found_risky)}"
                    if found_risky
                    else "No obviously risky services detected in process list."
                ),
                evidence=f"Risky services found: {found_risky}\nAll processes (sample): {services_list[:50]}",
                remediation=(
                    "Disable legacy/insecure services such as telnet, FTP, and rsh. "
                    "Replace with SSH/SFTP equivalents."
                ),
                test_run="running_services",
                rationale="Legacy services transmit credentials and data in cleartext.",
                methodology="Enumerated process names via psutil and systemctl.",
                status="fail" if found_risky else "pass",
                compliance_tags=["NIST-PR.AC-5", "HIPAA-164.312(e)(1)", "NIST-CSF-PR.IP-1"],
                metadata={"risky": found_risky},
            )
        ]

    # ------------------------------------------------------------------ #
    # Open ports (local)                                                   #
    # ------------------------------------------------------------------ #

    def _check_open_ports_local(self) -> list[Finding]:
        """List locally listening TCP/UDP ports."""
        listening: list[dict[str, Any]] = []

        if _PSUTIL_AVAILABLE:
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.status in ("LISTEN", psutil.CONN_LISTEN) or (
                        conn.type == socket.SOCK_DGRAM and conn.laddr
                    ):
                        listening.append(
                            {
                                "ip": conn.laddr.ip,
                                "port": conn.laddr.port,
                                "pid": conn.pid,
                                "status": conn.status,
                            }
                        )
            except Exception as exc:
                self._log.debug("net_connections error: %s", exc)

        evidence = "\n".join(
            f"  {c['ip']}:{c['port']} (pid={c['pid']}, status={c['status']})"
            for c in listening
        )

        return [
            Finding(
                title="Locally Listening Ports",
                severity="Informational",
                description=f"{len(listening)} listening port(s) found on this host.",
                evidence=evidence or "Could not enumerate listening ports (may need elevated privileges).",
                remediation="Review all listening ports and disable any that are unnecessary.",
                test_run="local_open_ports",
                rationale="Reducing the attack surface requires knowing what ports are exposed.",
                methodology="Enumerated network connections via psutil.net_connections().",
                status="pass",
                compliance_tags=["NIST-PR.AC-5", "NIST-ID.AM-3"],
                metadata={"listening": listening},
            )
        ]
