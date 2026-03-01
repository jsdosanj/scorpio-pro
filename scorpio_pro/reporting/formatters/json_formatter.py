"""JSON report formatter for Scorpio Pro — machine-readable SIEM-compatible output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import Finding


def generate(
    findings: list[Finding],
    compliance_results: dict[str, Any],
    scope: Any,
    output_path: Path,
) -> Path:
    """Write a JSON report to *output_path*.

    Args:
        findings: All scan findings.
        compliance_results: Framework evaluation results.
        scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.
        output_path: Destination .json file path.

    Returns:
        Path to the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    report = {
        "scorpio_pro_version": "1.0.0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "engagement": {
            "name": getattr(scope, "engagement_name", ""),
            "authorised_by": getattr(scope, "authorised_by", ""),
            "authorisation_date": getattr(scope, "authorisation_date", ""),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
        },
        "findings": [f.to_dict() for f in findings],
        "compliance": compliance_results,
    }

    output_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )
    return output_path
