"""Structured logging framework for Scorpio Pro with color-coded console output."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    _COLORAMA_AVAILABLE = False

try:
    from rich.logging import RichHandler
    from rich.console import Console
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

_LOG_COLORS: dict[str, str] = {
    "DEBUG": Fore.CYAN if _COLORAMA_AVAILABLE else "",
    "INFO": Fore.GREEN if _COLORAMA_AVAILABLE else "",
    "WARNING": Fore.YELLOW if _COLORAMA_AVAILABLE else "",
    "ERROR": Fore.RED if _COLORAMA_AVAILABLE else "",
    "CRITICAL": Fore.MAGENTA if _COLORAMA_AVAILABLE else "",
}
_RESET = Style.RESET_ALL if _COLORAMA_AVAILABLE else ""


class ColorFormatter(logging.Formatter):
    """Custom formatter that adds color coding to log levels."""

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        """Format the log record with color-coded level name."""
        color = _LOG_COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname:<8}{_RESET}"
        return super().format(record)


def get_logger(
    name: str = "scorpio_pro",
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    use_rich: bool = True,
) -> logging.Logger:
    """Create and configure a logger instance.

    Args:
        name: Logger name (typically the module name).
        level: Logging level (e.g., logging.DEBUG).
        log_file: Optional path to write log file.
        use_rich: Whether to use Rich handler for pretty console output.

    Returns:
        Configured :class:`logging.Logger` instance.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # Console handler
    if use_rich and _RICH_AVAILABLE:
        console_handler: logging.Handler = RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_level=True,
            show_path=False,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s", datefmt=datefmt))
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(ColorFormatter(fmt=fmt, datefmt=datefmt))

    console_handler.setLevel(level)
    logger.addHandler(console_handler)

    # File handler
    if log_file is not None:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


# Module-level default logger
logger = get_logger("scorpio_pro")
