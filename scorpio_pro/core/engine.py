"""Main orchestration engine for Scorpio Pro scans."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from scorpio_pro.core.logger import get_logger
from scorpio_pro.core.plugin_manager import discover_scanners
from scorpio_pro.scanners.base_scanner import Finding

logger = get_logger("scorpio_pro.engine")


class ScanEngine:
    """Orchestrates discovery, execution, and aggregation of scanner results.

    The engine:
    1. Discovers all available scanner classes via the plugin manager.
    2. Runs each scanner sequentially, collecting :class:`~scorpio_pro.scanners.base_scanner.Finding` objects.
    3. Passes aggregated findings to the compliance engine.
    4. Invokes the report generator.

    Args:
        scope: A :class:`~scorpio_pro.config.scope.ScopeConfig` instance.
        settings: Optional :class:`~scorpio_pro.config.settings.Settings` override.
    """

    def __init__(self, scope: Any, settings: Any = None) -> None:
        from scorpio_pro.config.settings import DEFAULT_SETTINGS

        self.scope = scope
        self.settings = settings or DEFAULT_SETTINGS
        self.findings: list[Finding] = []
        self._start_time: float = 0.0
        self._end_time: float = 0.0

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def run(
        self,
        report_formats: list[str] | None = None,
        output_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Execute the full scan pipeline.

        Args:
            report_formats: Desired output formats, e.g. ``["html", "json", "txt"]``.
            output_dir: Directory to write reports. Defaults to ``settings.output_dir``.

        Returns:
            Summary dict with ``findings``, ``compliance``, and ``report_paths`` keys.
        """
        report_formats = report_formats or self.settings.report_formats
        output_dir = Path(output_dir or self.settings.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self._start_time = time.time()
        logger.info("=" * 70)
        logger.info("Scorpio Pro scan started for: %s", self.scope.engagement_name)
        logger.info("=" * 70)

        self.findings = self._run_scanners()
        compliance_results = self._run_compliance(self.findings)
        report_paths = self._generate_reports(
            self.findings, compliance_results, report_formats, output_dir
        )

        self._end_time = time.time()
        elapsed = self._end_time - self._start_time
        logger.info(
            "Scan complete in %.1f seconds. %d findings. Reports: %s",
            elapsed,
            len(self.findings),
            ", ".join(str(p) for p in report_paths),
        )

        return {
            "findings": self.findings,
            "compliance": compliance_results,
            "report_paths": report_paths,
            "elapsed_seconds": elapsed,
        }

    # ------------------------------------------------------------------ #
    # Internal pipeline steps                                             #
    # ------------------------------------------------------------------ #

    def _run_scanners(self) -> list[Finding]:
        """Discover and execute all available scanners."""
        scanner_classes = discover_scanners()
        all_findings: list[Finding] = []

        total = len(scanner_classes)
        for idx, cls in enumerate(scanner_classes, start=1):
            scanner = cls()
            logger.info(
                "[%d/%d] Running scanner: %s", idx, total, getattr(cls, "name", cls.__name__)
            )

            if not scanner.check_prerequisites():
                logger.warning(
                    "Skipping %s: prerequisites not met.", cls.__name__
                )
                continue

            try:
                findings = scanner.run(self.scope)
                logger.info(
                    "  → %s produced %d finding(s).", cls.__name__, len(findings)
                )
                all_findings.extend(findings)
            except Exception as exc:  # noqa: BLE001
                logger.error("Scanner %s raised an error: %s", cls.__name__, exc, exc_info=True)

        return all_findings

    def _run_compliance(self, findings: list[Finding]) -> dict[str, Any]:
        """Map findings to compliance frameworks and calculate scores."""
        try:
            from scorpio_pro.compliance.engine import ComplianceEngine
            engine = ComplianceEngine()
            return engine.evaluate(findings)
        except Exception as exc:  # noqa: BLE001
            logger.error("Compliance engine error: %s", exc, exc_info=True)
            return {}

    def _generate_reports(
        self,
        findings: list[Finding],
        compliance: dict[str, Any],
        formats: list[str],
        output_dir: Path,
    ) -> list[Path]:
        """Invoke the report generator for each requested format."""
        try:
            from scorpio_pro.reporting.report_generator import ReportGenerator
            gen = ReportGenerator(
                findings=findings,
                compliance_results=compliance,
                scope=self.scope,
                output_dir=output_dir,
            )
            return gen.generate(formats=formats)
        except Exception as exc:  # noqa: BLE001
            logger.error("Report generator error: %s", exc, exc_info=True)
            return []
