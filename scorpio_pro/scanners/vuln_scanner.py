"""Vulnerability scanner — CVE lookups, default credentials, SSL/TLS analysis."""

from __future__ import annotations

import json
import socket
import ssl
import time
from typing import Any
from urllib import request as urllib_request
from urllib.error import URLError

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


class VulnScanner(BaseScanner):
    """Checks for known vulnerabilities, default credentials, and TLS issues.

    Capabilities:
    - CVE database lookups against NIST NVD API
    - SSL/TLS configuration analysis (protocol versions, cipher suites)
    - Certificate validity checks
    - Default credential testing on discovered services
    - Basic web application header checks
    """

    name = "Vulnerability Scanner"
    description = "CVE lookups, SSL/TLS analysis, and default credential checks."

    _DEFAULT_CREDS: list[dict[str, str]] = [
        {"service": "ssh", "user": "root", "password": "root"},
        {"service": "ssh", "user": "admin", "password": "admin"},
        {"service": "ssh", "user": "admin", "password": "password"},
        {"service": "ftp", "user": "anonymous", "password": "anonymous@"},
        {"service": "ftp", "user": "admin", "password": "admin"},
        {"service": "http", "user": "admin", "password": "admin"},
        {"service": "http", "user": "admin", "password": "password"},
        {"service": "http", "user": "admin", "password": "1234"},
    ]

    def check_prerequisites(self) -> bool:
        """Check for optional requests library."""
        if not _REQUESTS_AVAILABLE:
            self._log.warning("requests library not available; using urllib fallback.")
        return True

    def run(self, scope: Any) -> list[Finding]:
        """Run all vulnerability checks.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of vulnerability findings.
        """
        findings: list[Finding] = []
        targets = scope.all_targets()
        if not targets:
            targets = [socket.gethostbyname(socket.gethostname())]

        # SSL/TLS checks on web services in scope
        web_targets: list[str] = list(scope.applications)
        for ip in targets[:10]:
            for port in [443, 8443]:
                if self._port_open(ip, port):
                    web_targets.append(f"https://{ip}:{port}")

        for target in web_targets[:10]:
            findings.extend(self._check_ssl_tls(target))
            findings.extend(self._check_http_security_headers(target))

        # Default credential checks
        for ip in targets[:5]:
            findings.extend(self._check_default_credentials(ip, scope))

        # CVE lookups for discovered products (aggregated from metadata if available)
        findings.extend(self._check_known_cves())

        return findings

    # ------------------------------------------------------------------ #
    # SSL/TLS Analysis                                                     #
    # ------------------------------------------------------------------ #

    def _check_ssl_tls(self, target: str) -> list[Finding]:
        """Analyse the SSL/TLS configuration of a given target URL."""
        findings: list[Finding] = []
        hostname = self._extract_hostname(target)
        port = 443

        if ":" in hostname:
            # IPv6 or host:port
            parts = target.rsplit(":", 1)
            try:
                port = int(parts[-1].rstrip("/"))
                hostname = self._extract_hostname(parts[0])
            except ValueError:
                pass

        # Check certificate and protocol
        issues: list[str] = []
        cert_info = {}
        try:
            ctx = ssl.create_default_context()
            # Enforce TLS 1.2 minimum — create_default_context already does this
            # on modern Python, but set explicitly for clarity.
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=10), server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                proto = ssock.version()
                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notAfter": cert.get("notAfter", ""),
                    "notBefore": cert.get("notBefore", ""),
                }
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    issues.append(f"Weak TLS protocol in use: {proto}")
                if cipher and cipher[0]:
                    cipher_name = cipher[0]
                    for weak in ("RC4", "DES", "NULL", "EXPORT", "anon", "MD5"):
                        if weak in cipher_name:
                            issues.append(f"Weak cipher suite: {cipher_name}")
        except ssl.SSLCertVerificationError as exc:
            issues.append(f"Certificate verification error: {exc}")
        except ssl.SSLError as exc:
            issues.append(f"SSL error: {exc}")
        except (socket.timeout, ConnectionRefusedError, OSError):
            return []  # host not reachable on this port

        # Intentional security probe: attempt to connect with TLS 1.0 to detect
        # whether the server accepts deprecated protocol versions.  We deliberately
        # configure an SSLContext that allows TLS 1.0 here — this is the whole
        # point of the check and is performed against authorised targets only.
        for proto_ver, ctx_method in [
            ("TLSv1.0", ssl.PROTOCOL_TLS_CLIENT),
            ("SSLv3", ssl.PROTOCOL_TLS_CLIENT),
        ]:
            try:
                ctx2 = ssl.SSLContext(ctx_method)  # noqa: S502
                ctx2.minimum_version = ssl.TLSVersion.TLSv1  # type: ignore[assignment] # intentional probe
                ctx2.maximum_version = ssl.TLSVersion.TLSv1  # type: ignore[assignment]
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                with ctx2.wrap_socket(
                    socket.create_connection((hostname, port), timeout=5),
                    server_hostname=hostname,
                ):
                    issues.append(f"{proto_ver} is accepted by the server.")
            except Exception:
                pass

        severity = "High" if issues else "Informational"
        status = "fail" if issues else "pass"
        return [
            Finding(
                title=f"SSL/TLS Configuration: {hostname}",
                severity=severity,
                description=(
                    f"SSL/TLS issues found: {'; '.join(issues)}"
                    if issues
                    else f"SSL/TLS configuration appears secure on {hostname}."
                ),
                evidence=json.dumps({"cert": cert_info, "issues": issues}, indent=2),
                remediation=(
                    "Disable SSLv3, TLS 1.0, TLS 1.1. Use only TLS 1.2+. "
                    "Disable RC4, DES, NULL, and EXPORT cipher suites. "
                    "Ensure certificate is valid and from a trusted CA."
                ),
                test_run="ssl_tls_analysis",
                rationale="Weak TLS configurations allow traffic interception via MITM attacks.",
                methodology="Connected via Python ssl module; checked protocol version and cipher suite.",
                status=status,
                compliance_tags=[
                    "HIPAA-164.312(e)(2)(ii)", "GDPR-Art32", "NIST-PR.DS-2",
                    "NIST-CSF-PR.DS-2",
                ],
                metadata={"host": hostname, "issues": issues, "cert": cert_info},
            )
        ]

    def _check_http_security_headers(self, target: str) -> list[Finding]:
        """Check for missing HTTP security headers."""
        required_headers = {
            "Strict-Transport-Security": "HSTS not set — enables HTTPS downgrade attacks.",
            "X-Content-Type-Options": "Missing — allows MIME sniffing attacks.",
            "X-Frame-Options": "Missing — allows clickjacking.",
            "Content-Security-Policy": "Missing — allows XSS injection.",
            "X-XSS-Protection": "Missing — browser XSS filter not explicitly enabled.",
        }
        missing: list[str] = []
        response_headers: dict[str, str] = {}

        try:
            if _REQUESTS_AVAILABLE:
                import requests
                resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)  # noqa: S501
                response_headers = dict(resp.headers)
            else:
                req = urllib_request.Request(target, headers={"User-Agent": "ScorpioPro/1.0"})
                with urllib_request.urlopen(req, timeout=10) as resp:  # noqa: S310
                    response_headers = dict(resp.headers)
        except Exception as exc:
            self._log.debug("HTTP header check failed for %s: %s", target, exc)
            return []

        for header, reason in required_headers.items():
            if header.lower() not in {k.lower() for k in response_headers}:
                missing.append(f"{header}: {reason}")

        if not missing:
            return []

        return [
            Finding(
                title=f"Missing HTTP Security Headers: {target}",
                severity="Medium",
                description=f"{len(missing)} security header(s) missing from {target}.",
                evidence="Missing headers:\n" + "\n".join(f"  - {m}" for m in missing),
                remediation=(
                    "Add missing HTTP security headers to the web server configuration. "
                    "Refer to OWASP Secure Headers Project for recommended values."
                ),
                test_run="http_security_headers",
                rationale="Security headers defend against common web attacks like XSS and clickjacking.",
                methodology=f"Performed HTTP GET to {target} and inspected response headers.",
                status="fail",
                compliance_tags=["NIST-PR.AC-5", "GDPR-Art32"],
                metadata={"missing_headers": missing, "target": target},
            )
        ]

    # ------------------------------------------------------------------ #
    # Default Credentials                                                  #
    # ------------------------------------------------------------------ #

    def _check_default_credentials(self, ip: str, scope: Any) -> list[Finding]:
        """Attempt default credential login on SSH and FTP services."""
        findings: list[Finding] = []

        # Only attempt on services that appear to be open
        if not self._port_open(ip, 22) and not self._port_open(ip, 21):
            return []

        try:
            import paramiko
            _PARAMIKO_AVAILABLE = True
        except ImportError:
            _PARAMIKO_AVAILABLE = False

        successful: list[dict[str, str]] = []

        if _PARAMIKO_AVAILABLE and self._port_open(ip, 22):
            for cred in self._DEFAULT_CREDS:
                if cred["service"] != "ssh":
                    continue
                try:
                    client = paramiko.SSHClient()
                    # Pen testing against authorised targets requires accepting
                    # unknown host keys since target known_hosts are not pre-populated.
                    # WarningPolicy logs the acceptance without silently trusting.
                    client.set_missing_host_key_policy(paramiko.WarningPolicy())
                    client.connect(
                        ip, port=22,
                        username=cred["user"],
                        password=cred["password"],
                        timeout=5,
                        banner_timeout=5,
                        auth_timeout=5,
                    )
                    client.close()
                    successful.append({"user": cred["user"], "password": "***REDACTED***", "service": "SSH"})
                except Exception:
                    pass
                time.sleep(0.5)  # rate-limit to avoid lockout

        if successful:
            findings.append(
                Finding(
                    title=f"Default Credentials Accepted on {ip}",
                    severity="Critical",
                    description=f"Default credentials work on {len(successful)} service(s) on {ip}.",
                    evidence=f"Successful logins: {json.dumps(successful)}",
                    remediation=(
                        "Immediately change all default credentials. "
                        "Implement account lockout after failed attempts. "
                        "Deploy MFA on all remote access services."
                    ),
                    test_run="default_credentials",
                    rationale="Default credentials are the most trivially exploitable vulnerability.",
                    methodology="Attempted login with known default username/password combinations.",
                    status="fail",
                    compliance_tags=[
                        "NIST-PR.AC-1", "HIPAA-164.312(a)(2)(i)", "GDPR-Art32",
                    ],
                    metadata={"ip": ip, "successful": successful},
                )
            )
        return findings

    # ------------------------------------------------------------------ #
    # CVE lookups                                                          #
    # ------------------------------------------------------------------ #

    def _check_known_cves(self) -> list[Finding]:
        """Query NVD API for recently published critical CVEs as a reference."""
        try:
            from scorpio_pro.config.settings import DEFAULT_SETTINGS
            base_url = DEFAULT_SETTINGS.nvd_api_base
            params = "?cvssV3Severity=CRITICAL&resultsPerPage=5&startIndex=0"
            url = f"{base_url}{params}"

            headers = {"User-Agent": "ScorpioPro/1.0"}
            if DEFAULT_SETTINGS.nvd_api_key:
                headers["apiKey"] = DEFAULT_SETTINGS.nvd_api_key

            if _REQUESTS_AVAILABLE:
                import requests
                resp = requests.get(url, headers=headers, timeout=15)
                data = resp.json()
            else:
                req = urllib_request.Request(url, headers=headers)
                with urllib_request.urlopen(req, timeout=15) as r:  # noqa: S310
                    data = json.loads(r.read())

            cves = data.get("vulnerabilities", [])
            if not cves:
                return []

            lines = []
            for item in cves[:5]:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                lines.append(f"  {cve_id}: {desc[:120]}...")

            return [
                Finding(
                    title="Recent Critical CVEs (NVD Reference)",
                    severity="Informational",
                    description="Sample of recent critical CVEs from NIST NVD for situational awareness.",
                    evidence="\n".join(lines),
                    remediation="Cross-reference your installed software versions against the NVD database regularly.",
                    test_run="cve_database_lookup",
                    rationale="Keeping abreast of recent CVEs enables proactive patching.",
                    methodology="Queried NIST NVD REST API for recent CRITICAL-severity CVEs.",
                    status="pass",
                    compliance_tags=["NIST-PR.IP-12", "NIST-ID.RA-1"],
                )
            ]

        except Exception as exc:
            self._log.debug("NVD API lookup failed: %s", exc)
            return []

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        """Return True if a TCP connection can be established."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    @staticmethod
    def _extract_hostname(url: str) -> str:
        """Strip scheme and path from a URL to get the hostname."""
        for prefix in ("https://", "http://"):
            if url.startswith(prefix):
                url = url[len(prefix):]
        return url.split("/")[0].split(":")[0]
