"""Plain-text report formatter for Scorpio Pro."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import Finding


def _severity_label(severity: str) -> str:
    """Return an ASCII label for a severity level."""
    labels = {
        "Critical": "[!!!CRITICAL]",
        "High":     "[!! HIGH   ]",
        "Medium":   "[ ! MEDIUM ]",
        "Low":      "[   LOW    ]",
        "Informational": "[   INFO   ]",
    }
    return labels.get(severity, f"[{severity:^11}]")


def generate(
    findings: list[Finding],
    compliance_results: dict[str, Any],
    scope: Any,
    output_path: Path,
) -> Path:
    """Write a plain-text report to *output_path*.

    Args:
        findings: All scan findings.
        compliance_results: Framework evaluation results.
        scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.
        output_path: Destination .txt file path.

    Returns:
        Path to the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines = _build_report(findings, compliance_results, scope)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def _build_report(
    findings: list[Finding],
    compliance_results: dict[str, Any],
    scope: Any,
) -> list[str]:
    lines: list[str] = []
    bar = "=" * 80
    thin = "-" * 80
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Header ──────────────────────────────────────────────────────────
    lines += [
        bar,
        " SCORPIO PRO — PENETRATION TEST REPORT",
        bar,
        f" Engagement  : {getattr(scope, 'engagement_name', 'N/A')}",
        f" Authorised  : {getattr(scope, 'authorised_by', 'N/A')}",
        f" Generated   : {ts}",
        f" Tool version: Scorpio Pro 1.0.0",
        bar,
        "",
    ]

    # ── Executive Summary ───────────────────────────────────────────────
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines += [
        "EXECUTIVE SUMMARY",
        thin,
        f"Total Findings : {len(findings)}",
        f"  Critical     : {counts.get('Critical', 0)}",
        f"  High         : {counts.get('High', 0)}",
        f"  Medium       : {counts.get('Medium', 0)}",
        f"  Low          : {counts.get('Low', 0)}",
        f"  Informational: {counts.get('Informational', 0)}",
        "",
    ]

    # Risk score (0–100, lower is worse)
    severity_weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2, "Informational": 0}
    raw_penalty = sum(
        counts.get(sev, 0) * w for sev, w in severity_weights.items()
    )
    risk_score = max(0, 100 - raw_penalty)
    lines += [
        f"Risk Score     : {risk_score}/100  "
        f"({'CRITICAL' if risk_score < 30 else 'HIGH' if risk_score < 50 else 'MEDIUM' if risk_score < 70 else 'LOW' if risk_score < 85 else 'GOOD'})",
        "",
    ]

    # ── Compliance Scorecard ─────────────────────────────────────────────
    if compliance_results:
        lines += [bar, "COMPLIANCE SCORECARD", thin]
        for fw_name, fw_result in compliance_results.items():
            score = fw_result.get("score", "N/A")
            passed = fw_result.get("passed", 0)
            failed = fw_result.get("failed", 0)
            total = fw_result.get("total_controls", 0)
            bar_width = 40
            filled = int(bar_width * score / 100) if isinstance(score, int) else 0
            prog_bar = "█" * filled + "░" * (bar_width - filled)
            lines += [
                f"  {fw_name:<20} {score:>3}%  [{prog_bar}]  "
                f"Passed: {passed}/{total}  Failed: {failed}",
            ]
        lines += [""]

    # ── Findings ─────────────────────────────────────────────────────────
    lines += [bar, "DETAILED FINDINGS", thin]
    sorted_findings = sorted(
        findings,
        key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(f.severity, 5),
    )

    for idx, finding in enumerate(sorted_findings, start=1):
        lines += [
            f"Finding #{idx:03d}  {_severity_label(finding.severity)}  [{finding.status.upper()}]",
            f"Title       : {finding.title}",
            f"Test Run    : {finding.test_run}",
            f"Severity    : {finding.severity}",
            f"Status      : {finding.status}",
            "",
            "Rationale:",
            f"  {finding.rationale}",
            "",
            "Methodology:",
            f"  {finding.methodology}",
            "",
            "Description:",
        ]
        for dline in finding.description.splitlines():
            lines.append(f"  {dline}")
        lines += [
            "",
            "Evidence:",
        ]
        for eline in (finding.evidence or "N/A").splitlines():
            lines.append(f"  {eline}")
        lines += [
            "",
            "Remediation:",
        ]
        for rline in finding.remediation.splitlines():
            lines.append(f"  {rline}")
        if finding.compliance_tags:
            lines += [
                "",
                f"Compliance Tags: {', '.join(finding.compliance_tags)}",
            ]
        lines += [thin, ""]

    # ── Compliance Gaps ──────────────────────────────────────────────────
    if compliance_results:
        lines += [bar, "COMPLIANCE GAPS & REMEDIATION", thin]
        for fw_name, fw_result in compliance_results.items():
            gaps = fw_result.get("gaps", [])
            if not gaps:
                lines += [f"  {fw_name}: No gaps identified."]
                continue
            lines += [f"  {fw_name} Gaps:"]
            for gap in gaps:
                lines += [
                    f"    Control  : {gap['control']}",
                    f"    Title    : {gap['title']}",
                    f"    Remediate: {gap['remediation']}",
                    "",
                ]

    lines += ["", bar, "END OF REPORT", bar]
    return lines
