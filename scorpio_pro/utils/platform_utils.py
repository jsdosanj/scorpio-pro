"""Cross-platform utility functions for Scorpio Pro."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def get_os() -> str:
    """Return a normalised OS identifier string.

    Returns:
        One of ``"linux"``, ``"macos"``, ``"windows"``, or ``"unknown"``.
    """
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system in ("linux", "windows"):
        return system
    return "unknown"


def is_root() -> bool:
    """Return True if the current process is running with root/admin privileges.

    On Unix-like systems this checks for UID 0.
    On Windows it calls IsUserAnAdmin via ctypes.

    Returns:
        ``True`` if elevated; ``False`` otherwise.
    """
    if get_os() == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def normalise_path(path: str | Path) -> Path:
    """Expand user home, resolve env vars, and return an absolute Path.

    Args:
        path: Input path string or Path object.

    Returns:
        Resolved :class:`pathlib.Path`.
    """
    return Path(os.path.expandvars(os.path.expanduser(str(path)))).resolve()


def command_available(cmd: str) -> bool:
    """Check whether *cmd* is available in the system PATH.

    Args:
        cmd: Executable name (without arguments).

    Returns:
        ``True`` if the command can be found; ``False`` otherwise.
    """
    return shutil.which(cmd) is not None


def run_command(
    args: list[str],
    timeout: int = 30,
    check: bool = False,
) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr).

    Args:
        args: Command and arguments list.
        timeout: Maximum execution time in seconds.
        check: If ``True``, raise :exc:`subprocess.CalledProcessError` on failure.

    Returns:
        Tuple of ``(returncode, stdout, stderr)``.
    """
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."
    except FileNotFoundError:
        return -1, "", f"Command not found: {args[0]}"


def get_temp_dir() -> Path:
    """Return a platform-appropriate temporary directory path.

    Returns:
        Path to the system temporary directory.
    """
    import tempfile
    return Path(tempfile.gettempdir())


def python_version_ok(min_major: int = 3, min_minor: int = 11) -> bool:
    """Check that the running Python version meets the minimum requirement.

    Args:
        min_major: Minimum required major version.
        min_minor: Minimum required minor version.

    Returns:
        ``True`` if the current Python version is ≥ (min_major, min_minor).
    """
    return sys.version_info >= (min_major, min_minor)


def get_hostname() -> str:
    """Return the local machine hostname.

    Returns:
        Hostname string.
    """
    import socket
    return socket.gethostname()
