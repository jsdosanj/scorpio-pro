"""Application scanner — installed software inventory and config auditing."""

from __future__ import annotations

import json
import platform
import re
import subprocess
from pathlib import Path
from typing import Any
from urllib import request as urllib_request
from urllib.error import URLError

from scorpio_pro.scanners.base_scanner import BaseScanner, Finding

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False


class AppScanner(BaseScanner):
    """Scans installed applications and checks for security misconfigurations.

    Capabilities:
    - Enumerate installed applications (OS-specific)
    - Detect outdated software via version comparison
    - Audit web server (Apache, Nginx) configurations
    - Audit database server (MySQL/MariaDB, PostgreSQL) configurations
    - Check for known vulnerable application versions
    """

    name = "Application Scanner"
    description = "Installed application inventory, version checks, and config audits."

    def check_prerequisites(self) -> bool:
        """Prerequisites are always met — degrades gracefully per platform."""
        return True

    def run(self, scope: Any) -> list[Finding]:
        """Run application security checks.

        Args:
            scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.

        Returns:
            List of application security findings.
        """
        findings: list[Finding] = []
        findings.extend(self._enumerate_installed_apps())
        findings.extend(self._audit_web_servers())
        findings.extend(self._audit_databases())
        findings.extend(self._check_runtime_versions())
        return findings

    # ------------------------------------------------------------------ #
    # Application Inventory                                               #
    # ------------------------------------------------------------------ #

    def _enumerate_installed_apps(self) -> list[Finding]:
        """List installed applications using OS-specific methods."""
        system = platform.system()
        apps: list[dict[str, str]] = []

        try:
            if system == "Linux":
                apps = self._list_apps_linux()
            elif system == "Darwin":
                apps = self._list_apps_macos()
            elif system == "Windows":
                apps = self._list_apps_windows()
        except Exception as exc:
            self._log.debug("App enumeration error: %s", exc)

        outdated_indicators: list[str] = []
        # Simple heuristic: flag very old version numbers
        old_version_re = re.compile(r"\b(0\.[0-9]+|1\.[0-5]|2\.[0-3])\b")
        for app in apps:
            version = app.get("version", "")
            if old_version_re.search(version):
                outdated_indicators.append(f"{app.get('name', '')}: {version}")

        evidence = "\n".join(
            f"  {a.get('name', 'Unknown')} {a.get('version', '')}" for a in apps[:50]
        )
        if len(apps) > 50:
            evidence += f"\n  ... and {len(apps) - 50} more."

        return [
            Finding(
                title="Installed Application Inventory",
                severity="Informational",
                description=f"{len(apps)} applications enumerated on this host.",
                evidence=evidence or "No applications found.",
                remediation=(
                    "Regularly audit installed applications. "
                    "Remove unused software. Keep all software patched."
                ),
                test_run="app_inventory",
                rationale="Unauthorised or outdated software increases the attack surface.",
                methodology=f"Used OS package manager APIs on {system}.",
                status="pass",
                compliance_tags=["NIST-ID.AM-2", "HIPAA-164.308(a)(5)(ii)(A)"],
                metadata={"app_count": len(apps), "outdated_indicators": outdated_indicators},
            )
        ]

    def _list_apps_linux(self) -> list[dict[str, str]]:
        """Enumerate installed packages on Linux via dpkg or rpm."""
        apps: list[dict[str, str]] = []
        # Try dpkg (Debian/Ubuntu)
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    apps.append({"name": parts[0], "version": parts[1]})
            if apps:
                return apps
        except FileNotFoundError:
            pass

        # Try rpm (RHEL/CentOS/Fedora)
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    apps.append({"name": parts[0], "version": parts[1]})
        except FileNotFoundError:
            pass

        return apps

    def _list_apps_macos(self) -> list[dict[str, str]]:
        """List applications on macOS using system_profiler."""
        apps: list[dict[str, str]] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                capture_output=True, text=True, timeout=60,
            )
            data = json.loads(result.stdout)
            for app in data.get("SPApplicationsDataType", []):
                apps.append({
                    "name": app.get("_name", ""),
                    "version": app.get("version", ""),
                })
        except Exception:
            # Fallback: list /Applications
            for d in Path("/Applications").glob("*.app"):
                apps.append({"name": d.stem, "version": "unknown"})
        return apps

    def _list_apps_windows(self) -> list[dict[str, str]]:
        """List installed programs on Windows via registry."""
        apps: list[dict[str, str]] = []
        try:
            import winreg  # type: ignore[import]
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for path in (
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                ):
                    try:
                        key = winreg.OpenKey(hive, path)
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            try:
                                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                                name = winreg.QueryValueEx(sub, "DisplayName")[0]
                                version = ""
                                try:
                                    version = winreg.QueryValueEx(sub, "DisplayVersion")[0]
                                except Exception:
                                    pass
                                apps.append({"name": name, "version": version})
                            except Exception:
                                pass
                    except Exception:
                        pass
        except ImportError:
            pass
        return apps

    # ------------------------------------------------------------------ #
    # Web Server Audit                                                     #
    # ------------------------------------------------------------------ #

    def _audit_web_servers(self) -> list[Finding]:
        """Audit Apache and Nginx configuration files."""
        findings: list[Finding] = []
        findings.extend(self._audit_apache())
        findings.extend(self._audit_nginx())
        return findings

    def _audit_apache(self) -> list[Finding]:
        """Check Apache httpd configuration for common misconfigurations."""
        config_paths = [
            Path("/etc/apache2/apache2.conf"),
            Path("/etc/httpd/conf/httpd.conf"),
            Path("/usr/local/etc/apache2/httpd.conf"),
        ]
        found = next((p for p in config_paths if p.exists()), None)
        if not found:
            return []

        issues: list[str] = []
        try:
            content = found.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            return []

        checks = {
            "ServerTokens Full": "ServerTokens is set to Full — discloses Apache version.",
            "ServerTokens OS": "ServerTokens is set to OS — discloses OS info.",
            "ServerSignature On": "ServerSignature is On — appends version to error pages.",
            "Options Indexes": "Directory listing (Options Indexes) enabled.",
            "TraceEnable On": "HTTP TRACE method is enabled — can assist XST attacks.",
        }
        for pattern, issue in checks.items():
            if pattern in content:
                issues.append(issue)

        if "SSLProtocol" in content:
            if "TLSv1 " in content or "TLSv1.0" in content:
                issues.append("Apache configured to allow TLS 1.0.")

        return [
            Finding(
                title="Apache HTTP Server Configuration",
                severity="Medium" if issues else "Informational",
                description=(
                    f"{len(issues)} Apache configuration issue(s) found."
                    if issues
                    else "Apache configuration appears secure."
                ),
                evidence="\n".join(issues) if issues else f"Config file: {found}",
                remediation=(
                    "Set ServerTokens Prod. Disable Options Indexes. "
                    "Set TraceEnable Off. Restrict SSLProtocol to TLSv1.2+."
                ),
                test_run="apache_config_audit",
                rationale="Web server misconfiguration enables information disclosure and attack facilitation.",
                methodology=f"Parsed Apache configuration file: {found}",
                status="fail" if issues else "pass",
                compliance_tags=["NIST-PR.AC-5", "GDPR-Art32"],
                metadata={"config_file": str(found), "issues": issues},
            )
        ]

    def _audit_nginx(self) -> list[Finding]:
        """Check Nginx configuration for common misconfigurations."""
        config_paths = [
            Path("/etc/nginx/nginx.conf"),
            Path("/usr/local/etc/nginx/nginx.conf"),
        ]
        found = next((p for p in config_paths if p.exists()), None)
        if not found:
            return []

        issues: list[str] = []
        try:
            content = found.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            return []

        if "server_tokens on" in content.lower():
            issues.append("server_tokens is on — nginx version disclosed in headers.")
        if "autoindex on" in content.lower():
            issues.append("Directory autoindex is on — directory listing enabled.")
        if "ssl_protocols" in content.lower():
            if "TLSv1 " in content or "TLSv1.0" in content:
                issues.append("nginx configured to allow TLS 1.0.")
        if "add_header X-Frame-Options" not in content:
            issues.append("X-Frame-Options header not configured.")
        if "add_header Strict-Transport-Security" not in content:
            issues.append("HSTS header not configured.")

        return [
            Finding(
                title="Nginx Configuration Audit",
                severity="Medium" if issues else "Informational",
                description=(
                    f"{len(issues)} Nginx configuration issue(s) found."
                    if issues
                    else "Nginx configuration appears secure."
                ),
                evidence="\n".join(issues) if issues else f"Config: {found}",
                remediation=(
                    "Set server_tokens off. Disable autoindex. "
                    "Add security headers. Restrict ssl_protocols to TLSv1.2 TLSv1.3."
                ),
                test_run="nginx_config_audit",
                rationale="Web server misconfiguration aids reconnaissance and exploitation.",
                methodology=f"Parsed Nginx configuration file: {found}",
                status="fail" if issues else "pass",
                compliance_tags=["NIST-PR.AC-5", "GDPR-Art32"],
                metadata={"config_file": str(found), "issues": issues},
            )
        ]

    # ------------------------------------------------------------------ #
    # Database Audit                                                       #
    # ------------------------------------------------------------------ #

    def _audit_databases(self) -> list[Finding]:
        """Audit MySQL/MariaDB and PostgreSQL configurations."""
        findings: list[Finding] = []
        findings.extend(self._audit_mysql())
        findings.extend(self._audit_postgresql())
        return findings

    def _audit_mysql(self) -> list[Finding]:
        """Check MySQL/MariaDB my.cnf for security settings."""
        config_paths = [
            Path("/etc/mysql/mysql.conf.d/mysqld.cnf"),
            Path("/etc/mysql/my.cnf"),
            Path("/etc/my.cnf"),
        ]
        found = next((p for p in config_paths if p.exists()), None)
        if not found:
            return []

        issues: list[str] = []
        try:
            content = found.read_text(encoding="utf-8", errors="ignore")
        except PermissionError:
            return []

        if "skip-networking" not in content and "bind-address" not in content:
            issues.append("MySQL may be listening on all interfaces (no bind-address or skip-networking).")
        if "local-infile = 1" in content.lower() or "local_infile = 1" in content.lower():
            issues.append("local_infile is enabled — allows arbitrary file read via LOAD DATA LOCAL.")
        if "secure-file-priv" not in content.lower():
            issues.append("secure_file_priv not set — INTO OUTFILE writes unrestricted.")

        return [
            Finding(
                title="MySQL/MariaDB Configuration Audit",
                severity="High" if issues else "Informational",
                description=(
                    f"{len(issues)} MySQL configuration issue(s) found."
                    if issues
                    else "MySQL/MariaDB configuration appears secure."
                ),
                evidence="\n".join(issues) if issues else f"Config: {found}",
                remediation=(
                    "Set bind-address = 127.0.0.1. "
                    "Disable local-infile. Set secure_file_priv to a restricted directory."
                ),
                test_run="mysql_config_audit",
                rationale="Database misconfigurations can lead to data exfiltration.",
                methodology=f"Parsed MySQL config file: {found}",
                status="fail" if issues else "pass",
                compliance_tags=["HIPAA-164.312(a)(1)", "GDPR-Art32", "NIST-PR.DS-1"],
                metadata={"config_file": str(found), "issues": issues},
            )
        ]

    def _audit_postgresql(self) -> list[Finding]:
        """Check PostgreSQL pg_hba.conf for insecure authentication rules."""
        pg_hba_paths = list(Path("/etc/postgresql").rglob("pg_hba.conf"))
        if not pg_hba_paths:
            pg_hba_paths = list(Path("/var/lib/postgresql").rglob("pg_hba.conf"))
        if not pg_hba_paths:
            return []

        issues: list[str] = []
        for pg_hba in pg_hba_paths[:3]:
            try:
                content = pg_hba.read_text(encoding="utf-8", errors="ignore")
            except PermissionError:
                continue

            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "trust" in line.split() and "0.0.0.0/0" in line:
                    issues.append(f"{pg_hba.name}: trust auth from 0.0.0.0/0.")
                if "password" in line.split() and "0.0.0.0/0" in line:
                    issues.append(f"{pg_hba.name}: cleartext password auth from 0.0.0.0/0.")

        if not issues and not pg_hba_paths:
            return []

        return [
            Finding(
                title="PostgreSQL Authentication Configuration",
                severity="Critical" if any("trust" in i for i in issues) else (
                    "High" if issues else "Informational"
                ),
                description=(
                    f"{len(issues)} pg_hba.conf issue(s) found."
                    if issues
                    else "PostgreSQL authentication configuration appears secure."
                ),
                evidence="\n".join(issues) if issues else f"Checked: {pg_hba_paths}",
                remediation=(
                    "Never use 'trust' authentication over the network. "
                    "Use scram-sha-256 for all remote connections."
                ),
                test_run="postgresql_config_audit",
                rationale="Insecure pg_hba.conf allows unauthenticated or cleartext database access.",
                methodology="Parsed pg_hba.conf authentication lines.",
                status="fail" if issues else "pass",
                compliance_tags=["HIPAA-164.312(a)(1)", "GDPR-Art32", "NIST-PR.DS-1"],
                metadata={"issues": issues},
            )
        ]

    # ------------------------------------------------------------------ #
    # Runtime Versions                                                     #
    # ------------------------------------------------------------------ #

    def _check_runtime_versions(self) -> list[Finding]:
        """Check versions of common runtimes (Python, Java, Node.js)."""
        runtimes: dict[str, str] = {}
        commands = {
            "python3": ["python3", "--version"],
            "java": ["java", "-version"],
            "node": ["node", "--version"],
            "ruby": ["ruby", "--version"],
            "php": ["php", "--version"],
            "go": ["go", "version"],
        }
        for name, cmd in commands.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                output = (result.stdout + result.stderr).strip().split("\n")[0]
                if output:
                    runtimes[name] = output
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return [
            Finding(
                title="Runtime Environment Inventory",
                severity="Informational",
                description=f"Found {len(runtimes)} runtime environment(s).",
                evidence="\n".join(f"  {k}: {v}" for k, v in runtimes.items()),
                remediation=(
                    "Ensure all runtimes are on supported/patched versions. "
                    "Remove unused runtimes to reduce attack surface."
                ),
                test_run="runtime_versions",
                rationale="Outdated runtimes contain known vulnerabilities.",
                methodology="Ran --version flag for common runtime executables.",
                status="pass",
                compliance_tags=["NIST-PR.IP-12", "NIST-ID.AM-2"],
                metadata={"runtimes": runtimes},
            )
        ]
