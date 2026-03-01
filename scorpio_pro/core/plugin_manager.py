"""Dynamic plugin/scanner discovery and loading for Scorpio Pro."""

from __future__ import annotations

import importlib
import inspect
from typing import TYPE_CHECKING

from scorpio_pro.core.logger import get_logger

if TYPE_CHECKING:
    from scorpio_pro.scanners.base_scanner import BaseScanner

logger = get_logger("scorpio_pro.plugin_manager")

# Ordered list of scanner module names (relative to scorpio_pro.scanners)
_SCANNER_MODULES: list[str] = [
    "system_scanner",
    "network_scanner",
    "vuln_scanner",
    "remote_access_scanner",
    "cloud_scanner",
    "app_scanner",
    "shared_drive_scanner",
]


def discover_scanners() -> list[type["BaseScanner"]]:
    """Discover and return all available scanner classes.

    Iterates through the known scanner module list, imports each module, and
    extracts any class that inherits from :class:`~scorpio_pro.scanners.base_scanner.BaseScanner`
    and is not the abstract base itself.

    Returns:
        Ordered list of concrete scanner classes.
    """
    from scorpio_pro.scanners.base_scanner import BaseScanner

    scanners: list[type[BaseScanner]] = []

    for module_name in _SCANNER_MODULES:
        full_name = f"scorpio_pro.scanners.{module_name}"
        try:
            module = importlib.import_module(full_name)
        except ImportError as exc:
            logger.warning("Could not import scanner module '%s': %s", full_name, exc)
            continue

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, BaseScanner)
                and obj is not BaseScanner
                and obj.__module__ == full_name
            ):
                scanners.append(obj)
                logger.debug("Discovered scanner: %s", obj.__name__)

    return scanners


def load_scanner(module_name: str) -> type["BaseScanner"] | None:
    """Load a specific scanner class by module name.

    Args:
        module_name: Short module name (e.g. ``"system_scanner"``).

    Returns:
        The scanner class, or ``None`` if loading fails.
    """
    from scorpio_pro.scanners.base_scanner import BaseScanner

    full_name = f"scorpio_pro.scanners.{module_name}"
    try:
        module = importlib.import_module(full_name)
    except ImportError as exc:
        logger.error("Cannot load scanner '%s': %s", full_name, exc)
        return None

    for _, obj in inspect.getmembers(module, inspect.isclass):
        if (
            issubclass(obj, BaseScanner)
            and obj is not BaseScanner
            and obj.__module__ == full_name
        ):
            return obj

    logger.warning("No scanner class found in module '%s'.", full_name)
    return None


def check_scanner_prerequisites(
    scanners: list[type["BaseScanner"]],
) -> dict[str, bool]:
    """Instantiate each scanner class and run its prerequisites check.

    Args:
        scanners: List of scanner *classes* (not instances).

    Returns:
        Mapping of scanner name to prerequisites-satisfied boolean.
    """
    results: dict[str, bool] = {}
    for cls in scanners:
        try:
            instance = cls()
            ok = instance.check_prerequisites()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Prerequisites check failed for %s: %s", cls.__name__, exc)
            ok = False
        results[cls.__name__] = ok
    return results
