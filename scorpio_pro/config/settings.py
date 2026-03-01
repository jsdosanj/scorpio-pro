"""Global settings and defaults for Scorpio Pro."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    """Global application settings.

    Attributes:
        output_dir: Default directory for generated reports.
        log_dir: Directory where log files are written.
        log_level: Default logging level string.
        nvd_api_base: Base URL for NVD CVE API.
        nvd_api_key: Optional NVD API key for higher rate limits.
        request_timeout: HTTP request timeout in seconds.
        max_threads: Maximum worker threads for concurrent scanning.
        report_formats: Default report output formats.
    """

    output_dir: Path = field(default_factory=lambda: Path("./reports"))
    log_dir: Path = field(default_factory=lambda: Path("./logs"))
    log_level: str = "INFO"
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str = ""
    request_timeout: int = 30
    max_threads: int = 10
    report_formats: list[str] = field(default_factory=lambda: ["html", "json", "txt"])


# Singleton default settings instance
DEFAULT_SETTINGS = Settings()
