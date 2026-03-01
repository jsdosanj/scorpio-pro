"""Command-line interface for Scorpio Pro using Click."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

try:
    from rich.console import Console
    from rich.panel import Panel
    _RICH_AVAILABLE = True
    _console = Console()
except ImportError:
    _RICH_AVAILABLE = False
    _console = None  # type: ignore[assignment]

from scorpio_pro import __version__


# ── ASCII Banner ──────────────────────────────────────────────────────────────
_BANNER = r"""
  ____                     _         ____
 / ___|  ___ ___  _ __ _ __(_) ___   |  _ \ _ __ ___
 \___ \ / __/ _ \| '__| '_ \| |/ _ \  | |_) | '__/ _ \
  ___) | (_| (_) | |  | |_) | | (_) | |  __/| | | (_) |
 |____/ \___\___/|_|  | .__/|_|\___/  |_|   |_|  \___/
                       |_|
         State-of-the-art Penetration Testing & Security Auditing
"""


def _print_banner() -> None:
    if _RICH_AVAILABLE and _console:
        _console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
        _console.print(
            Panel.fit(
                f"[bold white]Scorpio Pro[/bold white] [dim]v{__version__}[/dim]",
                border_style="cyan",
            )
        )
    else:
        print(_BANNER)
        print(f"  Scorpio Pro v{__version__}\n")


# ── CLI Group ─────────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="scorpio-pro")
@click.pass_context
def main(ctx: click.Context) -> None:
    """🦂 Scorpio Pro — penetration testing and security auditing tool.

    Run 'scorpio-pro scan --help' for scanning options.
    """
    if ctx.invoked_subcommand is None:
        _print_banner()
        click.echo(ctx.get_help())


# ── scan command ─────────────────────────────────────────────────────────────
@main.command("scan")
@click.option(
    "--scope-config",
    "-s",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    required=False,
    help="Path to YAML scope configuration file.",
)
@click.option(
    "--report-format",
    "-f",
    default="html,json,txt",
    show_default=True,
    help="Comma-separated list of report formats: html, json, txt.",
)
@click.option(
    "--output-dir",
    "-o",
    default="./reports",
    show_default=True,
    type=click.Path(),
    help="Directory for generated reports.",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Skip the authorisation prompt (use in CI pipelines — ensure written auth exists).",
)
@click.option(
    "--log-level",
    default="INFO",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    show_default=True,
    help="Logging verbosity level.",
)
def scan(
    scope_config: Optional[str],
    report_format: str,
    output_dir: str,
    yes: bool,
    log_level: str,
) -> None:
    """Run a full security scan against the configured scope.

    \b
    Example:
        scorpio-pro scan --scope-config scope.yaml --report-format html,json --output-dir ./reports/
    """
    import logging
    from scorpio_pro.core.logger import get_logger
    from scorpio_pro.config.scope import ScopeConfig
    from scorpio_pro.config.authorization import prompt_authorisation
    from scorpio_pro.core.engine import ScanEngine

    _print_banner()
    log = get_logger("scorpio_pro", level=getattr(logging, log_level.upper()))

    # Load scope
    if scope_config:
        try:
            scope = ScopeConfig.from_yaml(scope_config)
        except Exception as exc:
            click.echo(f"[ERROR] Failed to load scope config: {exc}", err=True)
            sys.exit(1)
        errors = scope.validate()
        if errors:
            click.echo("[ERROR] Scope validation failed:", err=True)
            for e in errors:
                click.echo(f"  - {e}", err=True)
            sys.exit(1)
    else:
        log.info("No scope config provided — scanning localhost only.")
        import socket
        scope = ScopeConfig(
            ips=[socket.gethostbyname(socket.gethostname())],
            engagement_name="Local Scan",
        )

    # Authorisation prompt
    scope_summary = (
        f"{len(scope.ips)} IPs, "
        f"{len(scope.cidr_ranges)} CIDR ranges, "
        f"{len(scope.applications)} applications"
    )
    if not prompt_authorisation(
        engagement_name=scope.engagement_name,
        authorised_by=scope.authorised_by,
        scope_summary=scope_summary,
        non_interactive=yes,
    ):
        click.echo("Scan aborted — authorisation not confirmed.", err=True)
        sys.exit(1)

    # Run engine
    formats = [f.strip() for f in report_format.split(",") if f.strip()]
    engine = ScanEngine(scope=scope)
    result = engine.run(report_formats=formats, output_dir=Path(output_dir))

    click.echo(f"\n✅ Scan complete. {len(result['findings'])} finding(s).")
    for path in result.get("report_paths", []):
        click.echo(f"   📄 {path}")


# ── scope command ─────────────────────────────────────────────────────────────
@main.command("scope")
@click.option("--create", "action", flag_value="create", help="Interactively create a scope file.")
@click.option("--export", "action", flag_value="export", help="Export current scope to YAML.")
@click.option("--import", "import_path", type=click.Path(exists=True), default=None, help="Import and display a scope YAML file.")
@click.option("--validate", is_flag=True, default=False, help="Validate the imported scope file.")
@click.option("--output", "-o", default="scope.yaml", show_default=True, help="Output file path for --create or --export.")
def scope_cmd(action: Optional[str], import_path: Optional[str], validate: bool, output: str) -> None:
    """Manage scan scope configuration files.

    \b
    Examples:
        scorpio-pro scope --create
        scorpio-pro scope --export --output my_scope.yaml
        scorpio-pro scope --import scope.yaml --validate
    """
    from scorpio_pro.config.scope import ScopeConfig

    if import_path:
        try:
            sc = ScopeConfig.from_yaml(import_path)
            click.echo(f"✅ Loaded scope: {sc.engagement_name}")
            click.echo(f"   IPs         : {sc.ips}")
            click.echo(f"   CIDR ranges : {sc.cidr_ranges}")
            click.echo(f"   Applications: {sc.applications}")
            click.echo(f"   Exclusions  : {sc.exclusions}")
            click.echo(f"   Intensity   : {sc.intensity}")
            if validate:
                errors = sc.validate()
                if errors:
                    click.echo("❌ Validation errors:", err=True)
                    for e in errors:
                        click.echo(f"  - {e}", err=True)
                    sys.exit(1)
                else:
                    click.echo("✅ Scope validation passed.")
        except Exception as exc:
            click.echo(f"[ERROR] {exc}", err=True)
            sys.exit(1)
        return

    if action == "create":
        _interactive_scope_builder(output)
    elif action == "export":
        click.echo("No scope loaded. Use --import first or run with --create.")
    else:
        click.echo(click.get_current_context().get_help())


def _interactive_scope_builder(output_path: str) -> None:
    """Walk the user through creating a scope configuration file."""
    from scorpio_pro.config.scope import ScopeConfig
    import yaml as _yaml

    click.echo("\n🦂 Scorpio Pro — Interactive Scope Builder\n")

    name = click.prompt("Engagement name", default="My Engagement")
    authorised_by = click.prompt("Authorised by", default="")
    authorisation_date = click.prompt("Authorisation date (YYYY-MM-DD)", default="")

    ips_raw = click.prompt("In-scope IP addresses (comma-separated, or leave blank)", default="")
    ips = [ip.strip() for ip in ips_raw.split(",") if ip.strip()]

    cidrs_raw = click.prompt("In-scope CIDR ranges (comma-separated, or leave blank)", default="")
    cidrs = [c.strip() for c in cidrs_raw.split(",") if c.strip()]

    apps_raw = click.prompt("In-scope applications/URLs (comma-separated, or leave blank)", default="")
    apps = [a.strip() for a in apps_raw.split(",") if a.strip()]

    excl_raw = click.prompt("Exclusions (IPs or CIDRs, comma-separated)", default="")
    exclusions = [e.strip() for e in excl_raw.split(",") if e.strip()]

    intensity = click.prompt(
        "Scan intensity",
        type=click.Choice(["passive", "moderate", "aggressive"]),
        default="moderate",
    )

    sc = ScopeConfig(
        engagement_name=name,
        authorised_by=authorised_by,
        authorisation_date=authorisation_date,
        ips=ips,
        cidr_ranges=cidrs,
        applications=apps,
        exclusions=exclusions,
        intensity=intensity,
    )

    errors = sc.validate()
    if errors:
        click.echo("\n⚠️  Validation warnings:")
        for e in errors:
            click.echo(f"  - {e}")

    sc.to_yaml(output_path)
    click.echo(f"\n✅ Scope saved to: {output_path}")
