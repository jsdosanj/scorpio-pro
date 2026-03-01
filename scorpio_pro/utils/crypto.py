"""Cryptographic utility functions for Scorpio Pro."""

from __future__ import annotations

import hashlib
import hmac
import ssl
import socket
from typing import Any, Optional


def assess_cipher_strength(cipher_name: str) -> str:
    """Classify a TLS cipher suite as Strong, Acceptable, or Weak.

    Args:
        cipher_name: OpenSSL cipher suite name string.

    Returns:
        ``"Weak"``, ``"Acceptable"``, or ``"Strong"``.
    """
    cipher_upper = cipher_name.upper()
    weak_patterns = ("RC4", "DES", "NULL", "EXPORT", "ANON", "MD5", "3DES")
    acceptable_patterns = ("AES128", "SHA1", "SHA ")
    for pattern in weak_patterns:
        if pattern in cipher_upper:
            return "Weak"
    for pattern in acceptable_patterns:
        if pattern in cipher_upper:
            return "Acceptable"
    return "Strong"


def get_tls_info(hostname: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Retrieve TLS connection details from a remote host.

    Args:
        hostname: Target hostname.
        port: Target port (default 443).
        timeout: Socket timeout in seconds.

    Returns:
        Dict with keys: ``protocol``, ``cipher``, ``cert_subject``,
        ``cert_issuer``, ``cert_expiry``, ``issues``.
    """
    result: dict[str, Any] = {
        "protocol": None,
        "cipher": None,
        "cert_subject": {},
        "cert_issuer": {},
        "cert_expiry": None,
        "issues": [],
    }
    try:
        ctx = ssl.create_default_context()
        # Enforce TLS 1.2 minimum — create_default_context already does this on
        # modern Python, but set it explicitly to satisfy static analysis.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=timeout),
            server_hostname=hostname,
        ) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            result["protocol"] = ssock.version()
            result["cipher"] = cipher[0] if cipher else None
            result["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
            result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
            result["cert_expiry"] = cert.get("notAfter", "")
            # Check cipher strength
            if cipher and assess_cipher_strength(cipher[0]) == "Weak":
                result["issues"].append(f"Weak cipher: {cipher[0]}")
            # Check protocol
            if result["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3"):
                result["issues"].append(f"Deprecated TLS version: {result['protocol']}")
    except ssl.SSLCertVerificationError as exc:
        result["issues"].append(f"Certificate validation failed: {exc}")
    except (ssl.SSLError, socket.error) as exc:
        result["issues"].append(f"Connection error: {exc}")
    return result


def hash_file(path: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute the cryptographic hash of a file.

    Args:
        path: Filesystem path to the file.
        algorithm: Hash algorithm name (e.g. ``"sha256"``, ``"md5"``).

    Returns:
        Hex digest string, or ``None`` if the file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return None


def constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks.

    Args:
        val1: First string.
        val2: Second string.

    Returns:
        ``True`` if the strings are equal; ``False`` otherwise.
    """
    return hmac.compare_digest(val1.encode(), val2.encode())


def is_self_signed(cert_info: dict[str, Any]) -> bool:
    """Determine whether a certificate is self-signed.

    Args:
        cert_info: Certificate dict as returned by :func:`get_tls_info`.

    Returns:
        ``True`` if subject equals issuer; ``False`` otherwise.
    """
    return cert_info.get("cert_subject") == cert_info.get("cert_issuer")
