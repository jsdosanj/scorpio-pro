"""HTML report formatter using Jinja2 for Scorpio Pro."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path
from typing import Any

from scorpio_pro.scanners.base_scanner import Finding

try:
    from jinja2 import Environment, FileSystemLoader
    _JINJA2_AVAILABLE = True
except ImportError:
    _JINJA2_AVAILABLE = False


def generate(
    findings: list[Finding],
    compliance_results: dict[str, Any],
    scope: Any,
    output_path: Path,
) -> Path:
    """Write a rich HTML report to *output_path*.

    Uses the Jinja2 template ``report.html.j2``.  Falls back to a minimal
    inline HTML report if Jinja2 is unavailable.

    Args:
        findings: All scan findings.
        compliance_results: Framework evaluation results.
        scope: :class:`~scorpio_pro.config.scope.ScopeConfig` instance.
        output_path: Destination .html file path.

    Returns:
        Path to the written file.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    severity_weights = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2, "Informational": 0}
    raw_penalty = sum(severity_counts.get(sev, 0) * w for sev, w in severity_weights.items())
    risk_score = max(0, 100 - raw_penalty)

    sorted_findings = sorted(
        findings,
        key=lambda f: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}.get(
            f.severity, 5
        ),
    )

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    context = {
        "engagement_name": getattr(scope, "engagement_name", "Untitled"),
        "authorised_by": getattr(scope, "authorised_by", ""),
        "generated_at": ts,
        "risk_score": risk_score,
        "severity_counts": severity_counts,
        "findings": sorted_findings,
        "compliance_results": compliance_results,
        "total_findings": len(findings),
    }

    if _JINJA2_AVAILABLE:
        templates_dir = Path(__file__).parent.parent / "templates"
        env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=True,
        )
        try:
            template = env.get_template("report.html.j2")
            html = template.render(**context)
            output_path.write_text(html, encoding="utf-8")
            return output_path
        except Exception:
            pass  # fall through to inline

    # Inline fallback HTML
    html = _build_inline_html(context)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def _severity_color(severity: str) -> str:
    colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#2563eb",
        "Informational": "#6b7280",
    }
    return colors.get(severity, "#6b7280")


def _status_icon(status: str) -> str:
    icons = {"pass": "✅", "fail": "❌", "warning": "⚠️"}
    return icons.get(status, "ℹ️")


def _build_inline_html(ctx: dict[str, Any]) -> str:
    """Build a self-contained HTML report without Jinja2."""
    severity_counts = ctx["severity_counts"]
    compliance_results = ctx.get("compliance_results", {})

    # Build findings HTML
    findings_html = ""
    for idx, finding in enumerate(ctx["findings"], 1):
        color = _severity_color(finding.severity)
        icon = _status_icon(finding.status)
        tags_html = ", ".join(
            f'<span class="tag">{html_escape(t)}</span>' for t in finding.compliance_tags
        )
        findings_html += f"""
        <details class="finding">
          <summary>
            <span class="badge" style="background:{color}">{html_escape(finding.severity)}</span>
            {icon} <strong>#{idx:03d} {html_escape(finding.title)}</strong>
          </summary>
          <table>
            <tr><th>Test</th><td>{html_escape(finding.test_run)}</td></tr>
            <tr><th>Status</th><td>{html_escape(finding.status)}</td></tr>
            <tr><th>Rationale</th><td>{html_escape(finding.rationale)}</td></tr>
            <tr><th>Methodology</th><td>{html_escape(finding.methodology)}</td></tr>
            <tr><th>Description</th><td>{html_escape(finding.description)}</td></tr>
            <tr><th>Evidence</th><td><pre>{html_escape(finding.evidence)}</pre></td></tr>
            <tr><th>Remediation</th><td>{html_escape(finding.remediation)}</td></tr>
            <tr><th>Compliance</th><td>{tags_html}</td></tr>
          </table>
        </details>
        """

    # Build compliance scorecard HTML
    scorecard_html = ""
    for fw_name, fw_result in compliance_results.items():
        score = fw_result.get("score", 0)
        bar_color = "#16a34a" if score >= 80 else "#ca8a04" if score >= 50 else "#dc2626"
        scorecard_html += f"""
        <div class="score-card">
          <div class="fw-name">{fw_name}</div>
          <div class="score-bar-bg">
            <div class="score-bar" style="width:{score}%;background:{bar_color}"></div>
          </div>
          <div class="score-pct">{score}%</div>
          <div class="score-detail">
            Passed: {fw_result.get('passed',0)} /
            Failed: {fw_result.get('failed',0)} /
            Total: {fw_result.get('total_controls',0)}
          </div>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Scorpio Pro Report — {html_escape(ctx['engagement_name'])}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
    .container{{max-width:1200px;margin:0 auto;padding:2rem}}
    header{{background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:2rem;border-radius:12px;margin-bottom:2rem;border:1px solid #334155}}
    h1{{font-size:2rem;color:#38bdf8;margin-bottom:.5rem}}
    h2{{font-size:1.25rem;color:#94a3b8;font-weight:400}}
    .meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-top:1.5rem}}
    .meta-item{{background:#1e293b;padding:1rem;border-radius:8px;border:1px solid #334155}}
    .meta-label{{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:.05em}}
    .meta-value{{font-size:1rem;color:#e2e8f0;margin-top:.25rem}}
    .section{{background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;border:1px solid #334155}}
    .section-title{{font-size:1.1rem;font-weight:600;color:#38bdf8;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:1px solid #334155}}
    .summary-grid{{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem}}
    .sev-box{{text-align:center;padding:1rem;border-radius:8px;color:#fff}}
    .sev-box .count{{font-size:2rem;font-weight:700}}
    .sev-box .label{{font-size:.75rem;text-transform:uppercase;opacity:.8}}
    .finding{{background:#0f172a;border:1px solid #334155;border-radius:8px;margin-bottom:.75rem;overflow:hidden}}
    .finding summary{{padding:1rem;cursor:pointer;display:flex;align-items:center;gap:.75rem;list-style:none}}
    .finding summary::-webkit-details-marker{{display:none}}
    .finding summary:hover{{background:#1e293b}}
    .badge{{padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:600;color:#fff}}
    .finding table{{width:100%;border-collapse:collapse;padding:1rem}}
    .finding td,.finding th{{padding:.5rem 1rem;border-bottom:1px solid #1e293b;text-align:left;vertical-align:top}}
    .finding th{{width:130px;color:#64748b;font-weight:500;font-size:.85rem}}
    .finding pre{{background:#0f172a;padding:.75rem;border-radius:4px;overflow-x:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-all}}
    .tag{{background:#1e3a5f;color:#38bdf8;padding:.1rem .4rem;border-radius:3px;font-size:.75rem;margin-right:.25rem}}
    .risk-score{{font-size:3rem;font-weight:700;text-align:center;padding:1rem}}
    .score-card{{display:flex;align-items:center;gap:1rem;padding:.75rem 0;border-bottom:1px solid #334155}}
    .fw-name{{width:150px;font-size:.9rem;color:#94a3b8}}
    .score-bar-bg{{flex:1;height:12px;background:#334155;border-radius:6px;overflow:hidden}}
    .score-bar{{height:100%;border-radius:6px;transition:width .3s}}
    .score-pct{{width:50px;text-align:right;font-weight:600}}
    .score-detail{{width:200px;font-size:.75rem;color:#64748b}}
    footer{{text-align:center;color:#475569;font-size:.8rem;margin-top:2rem;padding:1rem}}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🦂 Scorpio Pro</h1>
      <h2>Penetration Test Report</h2>
      <div class="meta">
        <div class="meta-item">
          <div class="meta-label">Engagement</div>
          <div class="meta-value">{html_escape(ctx['engagement_name'])}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Authorised By</div>
          <div class="meta-value">{html_escape(ctx['authorised_by'] or 'N/A')}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Generated</div>
          <div class="meta-value">{html_escape(ctx['generated_at'])}</div>
        </div>
      </div>
    </header>

    <div class="section">
      <div class="section-title">Risk Score</div>
      <div class="risk-score" style="color:{'#16a34a' if ctx['risk_score']>=85 else '#ca8a04' if ctx['risk_score']>=50 else '#dc2626'}">
        {ctx['risk_score']}/100
      </div>
    </div>

    <div class="section">
      <div class="section-title">Finding Summary</div>
      <div class="summary-grid">
        <div class="sev-box" style="background:#dc2626">
          <div class="count">{severity_counts.get('Critical',0)}</div>
          <div class="label">Critical</div>
        </div>
        <div class="sev-box" style="background:#ea580c">
          <div class="count">{severity_counts.get('High',0)}</div>
          <div class="label">High</div>
        </div>
        <div class="sev-box" style="background:#ca8a04">
          <div class="count">{severity_counts.get('Medium',0)}</div>
          <div class="label">Medium</div>
        </div>
        <div class="sev-box" style="background:#2563eb">
          <div class="count">{severity_counts.get('Low',0)}</div>
          <div class="label">Low</div>
        </div>
        <div class="sev-box" style="background:#475569">
          <div class="count">{severity_counts.get('Informational',0)}</div>
          <div class="label">Info</div>
        </div>
      </div>
    </div>

    {'<div class="section"><div class="section-title">Compliance Scorecard</div>' + scorecard_html + '</div>' if scorecard_html else ''}

    <div class="section">
      <div class="section-title">Findings ({ctx['total_findings']})</div>
      {findings_html or '<p style="color:#64748b">No findings recorded.</p>'}
    </div>

    <footer>
      Generated by Scorpio Pro 1.0.0 &mdash; {ctx['generated_at']}
    </footer>
  </div>
</body>
</html>"""
