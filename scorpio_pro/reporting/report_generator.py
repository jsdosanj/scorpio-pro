"""Report generation orchestrator for Scorpio Pro."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scorpio_pro.core.logger import get_logger
from scorpio_pro.scanners.base_scanner import Finding

logger = get_logger("scorpio_pro.reporting")


class ReportGenerator:
    """Orchestrates report generation in multiple formats.

    Args:
        findings: List of all scan findings.
        compliance_results: Dict of framework evaluation results.
        scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.
        output_dir: Directory where reports will be written.
    """

    FORMAT_MAP = {
        "txt":  "scorpio_pro.reporting.formatters.txt_formatter",
        "text": "scorpio_pro.reporting.formatters.txt_formatter",
        "html": "scorpio_pro.reporting.formatters.html_formatter",
        "json": "scorpio_pro.reporting.formatters.json_formatter",
    }

    def __init__(
        self,
        findings: list[Finding],
        compliance_results: dict[str, Any],
        scope: Any,
        output_dir: Path = Path("./reports"),
    ) -> None:
        self.findings = findings
        self.compliance_results = compliance_results
        self.scope = scope
        self.output_dir = Path(output_dir)

    def generate(self, formats: list[str] | None = None) -> list[Path]:
        """Generate reports in the requested formats.

        Args:
            formats: List of format strings, e.g. ``["html", "json", "txt"]``.
                     Defaults to all three formats.

        Returns:
            List of paths to the generated report files.
        """
        import importlib

        formats = formats or ["html", "json", "txt"]
        self.output_dir.mkdir(parents=True, exist_ok=True)
        generated: list[Path] = []

        eng_slug = (
            getattr(self.scope, "engagement_name", "report")
            .lower()
            .replace(" ", "_")
            [:30]
        )

        for fmt in formats:
            fmt = fmt.lower().strip()
            module_path = self.FORMAT_MAP.get(fmt)
            if not module_path:
                logger.warning("Unknown report format '%s'; skipping.", fmt)
                continue

            # Use txt extension for both "txt" and "text"
            ext = "txt" if fmt in ("txt", "text") else fmt
            filename = f"{eng_slug}_report.{ext}"
            output_path = self.output_dir / filename

            try:
                module = importlib.import_module(module_path)
                path = module.generate(
                    findings=self.findings,
                    compliance_results=self.compliance_results,
                    scope=self.scope,
                    output_path=output_path,
                )
                generated.append(path)
                logger.info("Report written: %s", path)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to generate %s report: %s", fmt, exc, exc_info=True)

        return generated
