"""Scope configuration — defines what is authorised to be scanned."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ScopeConfig:
    """Encapsulates everything that is in-scope for a pen test engagement.

    Attributes:
        ips: Individual IPv4/IPv6 addresses.
        cidr_ranges: CIDR network ranges (e.g. ``192.168.1.0/24``).
        subnets: Subnet strings included in scope.
        ports: Specific ports or port ranges (e.g. ``"80"``, ``"1-1024"``).
        services: Named services to test (e.g. ``"ssh"``, ``"http"``).
        cloud_accounts: Cloud provider account IDs/names.
        applications: Application names / URLs to test.
        exclusions: Hosts / ranges explicitly excluded.
        intensity: Scan intensity — ``passive``, ``moderate``, or ``aggressive``.
        time_windows: Allowed scanning windows (list of dicts with start/end keys).
        engagement_name: Human-readable engagement title.
        authorised_by: Name of person who authorised the scan.
        authorisation_date: ISO date string.
    """

    ips: list[str] = field(default_factory=list)
    cidr_ranges: list[str] = field(default_factory=list)
    subnets: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=lambda: ["1-1024"])
    services: list[str] = field(default_factory=list)
    cloud_accounts: list[dict[str, Any]] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    intensity: str = "moderate"
    time_windows: list[dict[str, str]] = field(default_factory=list)
    engagement_name: str = "Untitled Engagement"
    authorised_by: str = ""
    authorisation_date: str = ""

    # ------------------------------------------------------------------ #
    # Factory methods                                                      #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeConfig":
        """Load scope configuration from a YAML file.

        Args:
            path: Path to the YAML scope file.

        Returns:
            Populated :class:`ScopeConfig` instance.

        Raises:
            FileNotFoundError: If *path* does not exist.
            yaml.YAMLError: If the file contains invalid YAML.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Scope file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            data: dict[str, Any] = yaml.safe_load(fh) or {}
        return cls(
            ips=data.get("ips", []),
            cidr_ranges=data.get("cidr_ranges", []),
            subnets=data.get("subnets", []),
            ports=data.get("ports", ["1-1024"]),
            services=data.get("services", []),
            cloud_accounts=data.get("cloud_accounts", []),
            applications=data.get("applications", []),
            exclusions=data.get("exclusions", []),
            intensity=data.get("intensity", "moderate"),
            time_windows=data.get("time_windows", []),
            engagement_name=data.get("engagement_name", "Untitled Engagement"),
            authorised_by=data.get("authorised_by", ""),
            authorisation_date=data.get("authorisation_date", ""),
        )

    def to_yaml(self, path: str | Path) -> None:
        """Export this scope configuration to a YAML file.

        Args:
            path: Destination file path.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "engagement_name": self.engagement_name,
            "authorised_by": self.authorised_by,
            "authorisation_date": self.authorisation_date,
            "intensity": self.intensity,
            "ips": self.ips,
            "cidr_ranges": self.cidr_ranges,
            "subnets": self.subnets,
            "ports": self.ports,
            "services": self.services,
            "cloud_accounts": self.cloud_accounts,
            "applications": self.applications,
            "exclusions": self.exclusions,
            "time_windows": self.time_windows,
        }
        with path.open("w", encoding="utf-8") as fh:
            yaml.dump(data, fh, default_flow_style=False, allow_unicode=True)

    # ------------------------------------------------------------------ #
    # Validation                                                           #
    # ------------------------------------------------------------------ #

    def validate(self) -> list[str]:
        """Validate the scope configuration and return a list of error messages.

        Returns:
            Empty list when the scope is valid; otherwise a list of error strings.
        """
        errors: list[str] = []

        for ip in self.ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append(f"Invalid IP address: {ip}")

        for cidr in self.cidr_ranges:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                errors.append(f"Invalid CIDR range: {cidr}")

        for exc in self.exclusions:
            try:
                ipaddress.ip_network(exc, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(exc)
                except ValueError:
                    errors.append(f"Invalid exclusion (not an IP or CIDR): {exc}")

        valid_intensities = {"passive", "moderate", "aggressive"}
        if self.intensity not in valid_intensities:
            errors.append(
                f"Invalid intensity '{self.intensity}'. "
                f"Must be one of: {', '.join(sorted(valid_intensities))}"
            )

        port_re = re.compile(r"^\d+(-\d+)?$")
        for port_spec in self.ports:
            if not port_re.match(str(port_spec)):
                errors.append(f"Invalid port specification: {port_spec}")

        return errors

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def is_in_scope(self, host: str) -> bool:
        """Check whether *host* is in-scope and not excluded.

        Args:
            host: IPv4/IPv6 address string.

        Returns:
            ``True`` if the host is authorised to be scanned.
        """
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return False

        # Check explicit exclusions first
        for exc in self.exclusions:
            try:
                if addr in ipaddress.ip_network(exc, strict=False):
                    return False
            except ValueError:
                if str(addr) == exc:
                    return False

        # Check individual IPs
        if host in self.ips:
            return True

        # Check CIDR ranges
        for cidr in self.cidr_ranges:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                pass

        return False

    def all_targets(self) -> list[str]:
        """Return a flat list of all in-scope IP addresses.

        Returns:
            Deduplicated list of IP address strings.
        """
        targets: list[str] = list(self.ips)
        for cidr in self.cidr_ranges:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                targets.extend(str(h) for h in net.hosts())
            except ValueError:
                pass
        # Remove excluded hosts
        return [t for t in dict.fromkeys(targets) if self.is_in_scope(t)]
