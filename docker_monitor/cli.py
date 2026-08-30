"""CLI entry point with subcommands."""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console

console = Console()


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])


def _load_config(config_path: str):
    from docker_monitor.config import Config
    return Config(config_path)


@click.group()
@click.option("--config", "-c", default="config.yaml", help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, config, verbose):
    """Docker Monitor v2.8 - Container Security Audit & Runtime Threat Monitoring."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config
    ctx.obj["verbose"] = verbose


@cli.command()
@click.pass_context
def audit(ctx):
    """Run a full multi-engine security audit."""
    config = _load_config(ctx.obj["config_path"])
    from docker_monitor.audit import run_audit
    summary = run_audit(config)
    vuln = summary.get("vulnerable", {})
    hard = summary.get("hardened", {})
    console.print("\n[bold green]Audit complete.[/bold green]")
    vr = vuln.get('ai_risk_score', 0)
    vc = vuln.get('critical', 0)
    vh = vuln.get('high', 0)
    hr = hard.get('ai_risk_score', 0)
    hc = hard.get('critical', 0)
    hh = hard.get('high', 0)
    console.print(f"  Vulnerable: risk={vr} critical={vc} high={vh}")
    console.print(f"  Hardened:   risk={hr} critical={hc} high={hh}")


@cli.command()
@click.option("--once", is_flag=True, help="Run a single monitoring cycle and exit")
@click.pass_context
def monitor(ctx, once):
    """Run the real-time runtime threat monitoring engine."""
    config = _load_config(ctx.obj["config_path"])
    from docker_monitor.monitor import RuntimeThreatEngine

    engine = RuntimeThreatEngine(config)
    if once:
        payload = engine.run_once()
        s = payload["summary"]
        console.print("\n[bold green]Snapshot complete.[/bold green]")
        cm = s['containers_monitored']
        cr = s['critical_alerts']
        hi = s['high_alerts']
        console.print(f"  Containers: {cm}  Critical: {cr}  High: {hi}")
    else:
        engine.run_forever()


@cli.command()
@click.option("--host", default=None, help="Dashboard host (default: from config)")
@click.option("--port", type=int, default=None, help="Dashboard port (default: from config)")
@click.pass_context
def dashboard(ctx, host, port):
    """Launch the web dashboard."""
    config = _load_config(ctx.obj["config_path"])
    from docker_monitor.dashboard.app import create_app

    app = create_app(config)
    dash_cfg = config.dashboard
    h = host or dash_cfg.get("host", "0.0.0.0")
    p = port or dash_cfg.get("port", 8080)
    console.print(f"[bold cyan]Dashboard starting on http://{h}:{p}[/bold cyan]")
    app.run(host=h, port=p, debug=False)


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "html"]), default="json", help="Report format")
@click.option("--output", "-o", default=None, help="Output directory")
@click.pass_context
def report(ctx, fmt, output):
    """Generate a report from the latest audit data."""
    config = _load_config(ctx.obj["config_path"])
    output_dir = output or config.reporting.get("output_dir", "reports")

    import json
    from pathlib import Path  # noqa: F811

    from docker_monitor.reports import ReportGenerator

    summary_path = Path(output_dir) / "latest_multi_engine_summary.json"
    if not summary_path.exists():
        console.print("[red]No audit data found. Run 'docker-monitor audit' first.[/red]")
        sys.exit(1)

    with open(summary_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    gen = ReportGenerator(output_dir)
    if fmt == "json":
        path = gen.generate_json_report(data)
    else:
        path = gen.generate_html_report(data)

    gen.update_history(data)
    console.print(f"[bold green]Report generated:[/bold green] {path}")


@cli.command()
@click.pass_context
def status(ctx):
    """Check tool availability and system status."""
    import shutil

    tools = ["docker", "trivy", "dockle", "syft", "grype", "python"]
    console.print("[bold]Tool Status[/bold]")
    for tool in tools:
        found = shutil.which(tool) is not None
        status_str = "[green]AVAILABLE[/green]" if found else "[red]MISSING[/red]"
        console.print(f"  {tool:<12} {status_str}")

    config = _load_config(ctx.obj["config_path"])
    console.print("\n[bold]Config[/bold]")
    console.print(f"  Config path: {ctx.obj['config_path']}")
    console.print(f"  Parallel scanning: {config.scanning.get('parallel', True)}")
    console.print(f"  Runtime monitoring: {config.runtime.get('enabled', True)}")
    console.print(f"  Alerting: {config.alerting.get('enabled', False)}")
    console.print(f"  ML model: {config.ml.get('enabled', False)}")


if __name__ == "__main__":
    cli()
