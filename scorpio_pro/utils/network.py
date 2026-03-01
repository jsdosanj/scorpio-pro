"""Network utility functions for Scorpio Pro."""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional


def is_valid_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 or IPv6 address.

    Args:
        address: IP address string to validate.

    Returns:
        ``True`` if the address is valid; ``False`` otherwise.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    """Return True if *cidr* is a valid CIDR range.

    Args:
        cidr: CIDR notation string (e.g. ``"192.168.0.0/24"``).

    Returns:
        ``True`` if valid; ``False`` otherwise.
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def cidr_to_hosts(cidr: str) -> list[str]:
    """Return list of host IP strings within a CIDR range.

    Args:
        cidr: CIDR notation string.

    Returns:
        List of host address strings (excludes network and broadcast).
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(h) for h in network.hosts()]
    except ValueError:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """Attempt a reverse DNS lookup for *ip*.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Hostname string, or ``None`` if lookup fails.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def forward_dns(hostname: str) -> list[str]:
    """Resolve *hostname* to a list of IP addresses.

    Args:
        hostname: DNS hostname to resolve.

    Returns:
        List of IP address strings; empty on failure.
    """
    try:
        return list({r[4][0] for r in socket.getaddrinfo(hostname, None)})
    except socket.gaierror:
        return []


def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check whether a TCP port is open on *host*.

    Args:
        host: Hostname or IP address.
        port: TCP port number.
        timeout: Connection timeout in seconds.

    Returns:
        ``True`` if the port accepted a connection; ``False`` otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def get_local_ip() -> str:
    """Return the primary outbound IP address of this machine.

    Returns:
        IP address string, or ``"127.0.0.1"`` as fallback.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def ip_in_range(ip: str, cidr: str) -> bool:
    """Check whether *ip* is within the CIDR range *cidr*.

    Args:
        ip: IPv4/IPv6 address string.
        cidr: CIDR range string.

    Returns:
        ``True`` if *ip* is within *cidr*; ``False`` otherwise.
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
