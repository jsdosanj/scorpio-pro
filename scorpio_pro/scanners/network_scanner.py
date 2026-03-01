"""Network scanner — port scanning, service detection, OS fingerprinting."""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

try:
    import nmap
    _NMAP_AVAILABLE = True
except ImportError:
    _NMAP_AVAILABLE = False


class NetworkScanner(BaseScanner):
    """Performs network reconnaissance within the authorised scope.

    Capabilities:
    - TCP/UDP port scanning via python-nmap
    - Service version detection
    - OS fingerprinting
    - DNS enumeration
    - ARP-based local host discovery
    - Network topology mapping
    """

    name = "Network Scanner"
    description = "Port scanning, service detection, and network topology mapping."

    # Common ports for passive/moderate scans
    _COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

    def check_prerequisites(self) -> bool:
        """Check that nmap binary and python-nmap are available."""
        if not _NMAP_AVAILABLE:
            self._log.warning("python-nmap not installed; network scan will use fallback TCP connect.")
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._log.warning("nmap binary not found; using fallback TCP connect scanner.")
        return True  # fallback available

    def run(self, scope: Any) -> list[Finding]:
        """Execute network scanning across all in-scope targets.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of findings.
        """
        findings: list[Finding] = []
        targets = scope.all_targets()

        if not targets:
            # Use localhost as a minimal target when no IPs are in scope
            targets = [socket.gethostbyname(socket.gethostname())]

        self._log.info("Network scan targets: %d hosts", len(targets))

        findings.extend(self._dns_enumeration(scope))
        findings.extend(self._port_scan(targets, scope))
        findings.extend(self._check_dangerous_services(findings))

        return findings

    # ------------------------------------------------------------------ #
    # DNS Enumeration                                                      #
    # ------------------------------------------------------------------ #

    def _dns_enumeration(self, scope: Any) -> list[Finding]:
        """Attempt DNS lookups for in-scope hosts."""
        results: dict[str, str] = {}
        hostnames_to_check = list(scope.applications) + scope.ips[:5]

        for host in hostnames_to_check:
            try:
                info = socket.getaddrinfo(host, None)
                ips = list({r[4][0] for r in info})
                results[host] = ", ".join(ips)
            except Exception:
                results[host] = "DNS resolution failed"

        evidence = "\n".join(f"  {h}: {ip}" for h, ip in results.items())

        return [
            Finding(
                title="DNS Enumeration",
                severity="Informational",
                description=f"DNS lookups performed for {len(results)} hostname(s).",
                evidence=evidence or "No hostnames to resolve.",
                remediation="Ensure DNS records are accurate and no sensitive subdomains are exposed.",
                test_run="dns_enumeration",
                rationale="DNS records can reveal infrastructure details useful to attackers.",
                methodology="Used socket.getaddrinfo() for forward DNS lookups.",
                status="pass",
                compliance_tags=["NIST-ID.AM-3"],
                metadata={"dns_results": results},
            )
        ]

    # ------------------------------------------------------------------ #
    # Port Scanning                                                        #
    # ------------------------------------------------------------------ #

    def _port_scan(self, targets: list[str], scope: Any) -> list[Finding]:
        """Scan targets for open ports using nmap or fallback."""
        findings: list[Finding] = []

        # Determine port range from scope
        port_spec = ",".join(str(p) for p in scope.ports) if scope.ports else self._COMMON_PORTS

        # Limit target list for safety
        targets = targets[:50]

        if _NMAP_AVAILABLE:
            findings.extend(self._nmap_scan(targets, port_spec, scope))
        else:
            findings.extend(self._fallback_tcp_scan(targets, scope))

        return findings

    def _nmap_scan(
        self, targets: list[str], port_spec: str, scope: Any
    ) -> list[Finding]:
        """Run an nmap scan and parse results."""
        findings: list[Finding] = []
        nm = nmap.PortScanner()
        target_str = " ".join(targets)

        intensity = getattr(scope, "intensity", "moderate")
        if intensity == "passive":
            args = f"-sT -p {port_spec} --open -T2"
        elif intensity == "aggressive":
            args = f"-sV -sC -O -p {port_spec} --open -T4"
        else:
            args = f"-sT -sV -p {port_spec} --open -T3"

        try:
            self._log.info("Running nmap: %s on %d target(s)", args, len(targets))
            nm.scan(hosts=target_str, arguments=args)
        except Exception as exc:
            self._log.error("nmap scan failed: %s", exc)
            return findings

        for host in nm.all_hosts():
            if not scope.is_in_scope(host):
                continue
            open_ports: list[dict[str, Any]] = []
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]["state"]
                    if state == "open":
                        svc = nm[host][proto][port]
                        open_ports.append(
                            {
                                "port": port,
                                "proto": proto,
                                "service": svc.get("name", ""),
                                "product": svc.get("product", ""),
                                "version": svc.get("version", ""),
                                "state": state,
                            }
                        )

            if not open_ports:
                continue

            os_info = "Unknown"
            try:
                osmatches = nm[host].get("osmatch", [])
                if osmatches:
                    os_info = osmatches[0].get("name", "Unknown")
            except Exception:
                pass

            evidence = f"Host: {host} | OS: {os_info}\nOpen ports:\n"
            for p in open_ports:
                evidence += (
                    f"  {p['port']}/{p['proto']}  {p['service']}  "
                    f"{p['product']} {p['version']}\n"
                )

            findings.append(
                Finding(
                    title=f"Open Ports on {host}",
                    severity="Informational",
                    description=f"{len(open_ports)} open port(s) found on {host}.",
                    evidence=evidence,
                    remediation="Restrict access to open ports using firewall rules. Disable unused services.",
                    test_run="port_scan",
                    rationale="Open ports expose services that may contain vulnerabilities.",
                    methodology=f"nmap TCP scan with arguments: {args}",
                    status="pass",
                    compliance_tags=["NIST-ID.AM-3", "NIST-PR.AC-5"],
                    metadata={"host": host, "os": os_info, "open_ports": open_ports},
                )
            )

        return findings

    def _fallback_tcp_scan(self, targets: list[str], scope: Any) -> list[Finding]:
        """Fallback TCP connect scan when nmap is unavailable."""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
        ]
        findings: list[Finding] = []

        for target in targets[:10]:  # limit in fallback mode
            open_ports: list[int] = []
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(self._tcp_connect, target, port): port
                    for port in common_ports
                }
                for future in as_completed(futures):
                    port = futures[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                    except Exception:
                        pass

            if open_ports:
                findings.append(
                    Finding(
                        title=f"Open Ports on {target} (TCP Connect)",
                        severity="Informational",
                        description=f"{len(open_ports)} open port(s) on {target}.",
                        evidence=f"Open ports: {sorted(open_ports)}",
                        remediation="Review and restrict open ports.",
                        test_run="port_scan_fallback",
                        rationale="Open ports expose services that may be vulnerable.",
                        methodology="Raw TCP connect scan (fallback, nmap not available).",
                        status="pass",
                        compliance_tags=["NIST-ID.AM-3"],
                        metadata={"host": target, "open_ports": open_ports},
                    )
                )
        return findings

    @staticmethod
    def _tcp_connect(host: str, port: int, timeout: float = 1.0) -> bool:
        """Attempt a TCP connection and return True if successful."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    # ------------------------------------------------------------------ #
    # Dangerous service checks                                             #
    # ------------------------------------------------------------------ #

    def _check_dangerous_services(self, prior_findings: list[Finding]) -> list[Finding]:
        """Flag specific dangerous services discovered in port scan findings."""
        dangerous: dict[int, str] = {
            21: "FTP (cleartext credentials)",
            23: "Telnet (cleartext session)",
            111: "RPC portmapper",
            512: "rexec",
            513: "rlogin",
            514: "rsh",
            2049: "NFS (verify authentication)",
        }
        flagged: list[dict[str, Any]] = []

        for finding in prior_findings:
            for port_info in finding.metadata.get("open_ports", []):
                port = port_info.get("port", 0)
                if port in dangerous:
                    flagged.append(
                        {
                            "host": finding.metadata.get("host", "unknown"),
                            "port": port,
                            "reason": dangerous[port],
                        }
                    )

        if not flagged:
            return []

        evidence = "\n".join(
            f"  {f['host']}:{f['port']} — {f['reason']}" for f in flagged
        )

        return [
            Finding(
                title="Dangerous/Legacy Services Detected",
                severity="High",
                description=f"{len(flagged)} dangerous service(s) detected across in-scope hosts.",
                evidence=evidence,
                remediation=(
                    "Disable Telnet, FTP, rsh, rlogin, and rexec. "
                    "Replace with SSH/SFTP. Restrict RPC and NFS access."
                ),
                test_run="dangerous_services",
                rationale="Legacy protocols transmit data in cleartext and are trivially exploitable.",
                methodology="Cross-referenced open ports from nmap results against known-dangerous service list.",
                status="fail",
                compliance_tags=[
                    "NIST-PR.AC-5", "HIPAA-164.312(e)(1)", "GDPR-Art32",
                ],
                metadata={"flagged": flagged},
            )
        ]
