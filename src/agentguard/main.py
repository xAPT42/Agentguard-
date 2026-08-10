"""AgentGuard command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from agentguard import __version__
from agentguard.datahub.lineage import build_lineage
from agentguard.datahub.skill import summarize
from agentguard.datahub.writer import _disclosure_compliant, write_assets_to_datahub
from agentguard.risk.narrative import annotate_narratives
from agentguard.risk.poison import annotate_assets
from agentguard.risk.propagation import propagate
from agentguard.risk.scorer import score_assets
from agentguard.scanner.agent_scanner import scan_agents
from agentguard.scanner.mcp_scanner import scan_mcp_servers

DEFAULT_OUTPUT = "scan_output.json"

TIER_STYLES = {
    "critical": "bold red",
    "high": "bold orange3",
    "medium": "bold yellow3",
    "low": "bold green",
}

STATUS_STYLES = {
    "ACTIVE": "green",
    "ORPHANED": "red",
    "UNKNOWN": "yellow",
}

OWASP_DESCRIPTIONS = {
    "LLM01": "Prompt Injection — untrusted content can steer this agent's shell or command tools.",
    "LLM06": "Sensitive Information Disclosure — this asset can reach secrets, files, or databases.",
    "LLM08": "Excessive Agency — the toolset grants more capability than the task requires.",
    "MCP03": "Tool Poisoning — the tool definitions this server serves carry hidden instructions.",
}

console = Console()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Discover AI agents and MCP servers, score their risk, publish to DataHub.",
    )
    parser.add_argument("--url", help="DataHub GMS URL (default: $DATAHUB_URL or http://localhost:8080)")
    parser.add_argument("--token", help="DataHub access token (default: $DATAHUB_TOKEN)")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"scan report path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--no-datahub", action="store_true", help="dry run: scan and score without writing to DataHub")
    parser.add_argument("--version", action="version", version=f"agentguard {__version__}")
    return parser.parse_args(argv)


def _scan_with_progress() -> list[dict[str, Any]]:
    steps = [
        ("Scanning MCP servers...", scan_mcp_servers),
        ("Scanning AI agents...", scan_agents),
    ]

    discovered: list[dict[str, Any]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        for description, step in steps:
            task = progress.add_task(description, total=None)
            discovered.extend(step())
            progress.remove_task(task)

        task = progress.add_task("Inspecting tool definitions...", total=None)
        annotate_assets(discovered)
        progress.remove_task(task)

        task = progress.add_task("Scoring assets...", total=None)
        scored = score_assets(discovered)
        progress.remove_task(task)

        task = progress.add_task("Propagating risk across the fleet...", total=None)
        propagate(scored)
        progress.remove_task(task)

        task = progress.add_task("Writing threat narratives...", total=None)
        annotate_narratives(scored)
        progress.remove_task(task)

    return scored


def _disclosure_cell(asset: dict[str, Any]) -> Text:
    value = _disclosure_compliant(asset)
    if value == "true":
        return Text("✓", style="green")
    if value == "false":
        return Text("✗", style="red")
    return Text("–", style="dim")


def _results_table(assets: list[dict[str, Any]]) -> Table:
    table = Table(box=ROUNDED, header_style="bold", expand=False)
    table.add_column("Name", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Tier", no_wrap=True)
    table.add_column("OWASP", no_wrap=True)
    table.add_column("EU AI Act", justify="center", no_wrap=True)

    for asset in assets:
        tier = str(asset.get("risk_tier", "low"))
        status = str(asset.get("status", "UNKNOWN"))
        tier_style = TIER_STYLES.get(tier, "white")

        table.add_row(
            str(asset.get("name", "unknown")),
            str(asset.get("type", "unknown")),
            Text(status, style=STATUS_STYLES.get(status, "white")),
            Text(str(asset.get("risk_score", 0)), style=tier_style),
            Text(tier, style=tier_style),
            ", ".join(asset.get("owasp_tags") or []) or "—",
            _disclosure_cell(asset),
        )
    return table


def _fleet_health(assets: list[dict[str, Any]]) -> int:
    if not assets:
        return 100
    average = sum(int(asset.get("risk_score", 0)) for asset in assets) / len(assets)
    return round(100 - average)


def _eu_ready(assets: list[dict[str, Any]]) -> int:
    return sum(1 for asset in assets if _disclosure_compliant(asset) != "false")


def _summary_panel(assets: list[dict[str, Any]], summary: dict[str, Any]) -> Panel:
    tiers = summary["by_risk_tier"]
    total = summary["total"]
    critical = tiers.get("critical", 0)
    high = tiers.get("high", 0)
    ready = _eu_ready(assets)
    ready_pct = round(ready / total * 100) if total else 100
    health = _fleet_health(assets)

    health_style = TIER_STYLES["low"] if health >= 75 else TIER_STYLES["medium"] if health >= 50 else TIER_STYLES["critical"]

    body = Text()
    body.append(f"{total}", style="bold")
    body.append(f" asset{'' if total == 1 else 's'}    ")
    body.append(f"{critical} critical", style=TIER_STYLES["critical"] if critical else "dim")
    body.append("    ")
    body.append(f"{high} high", style=TIER_STYLES["high"] if high else "dim")
    body.append("    ")
    body.append(f"EU AI Act ready {ready}/{total} ({ready_pct}%)")
    body.append("    ")
    body.append("fleet health ")
    body.append(f"{health}/100", style=health_style)

    return Panel(body, title="Fleet summary", border_style="cyan", box=ROUNDED)


def _owasp_panel(assets: list[dict[str, Any]]) -> Panel | None:
    counts: dict[str, int] = {}
    for asset in assets:
        for tag in asset.get("owasp_tags") or []:
            counts[tag] = counts.get(tag, 0) + 1

    if not counts:
        return None

    lines = []
    for tag in sorted(counts):
        line = Text()
        line.append(f"{tag}", style="bold")
        line.append(f"  ({counts[tag]} asset{'s' if counts[tag] > 1 else ''})  ", style="dim")
        line.append(OWASP_DESCRIPTIONS.get(tag, ""))
        lines.append(line)

    return Panel(Group(*lines), title="OWASP LLM Top 10 findings", border_style="magenta", box=ROUNDED)


def _critical_panel(assets: list[dict[str, Any]]) -> Panel:
    names = [str(a.get("name")) for a in assets if a.get("risk_tier") == "critical"]
    noun = "asset requires" if len(names) == 1 else "assets require"
    body = Text()
    body.append(f"{len(names)} critical {noun} attention:\n", style="bold red")
    body.append("  " + "\n  ".join(names))
    return Panel(body, title="Action required", border_style="red", box=ROUNDED)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    assets = _scan_with_progress()

    if not assets:
        console.print("[dim]No AI agents or MCP servers found.[/dim]")
        return 0

    assets.sort(key=lambda asset: asset.get("risk_score", 0), reverse=True)
    summary = summarize(assets)

    console.print()
    console.print(_results_table(assets))
    console.print(_summary_panel(assets, summary))

    owasp = _owasp_panel(assets)
    if owasp:
        console.print(owasp)

    report = {"version": __version__, "summary": summary, "assets": assets}
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        console.print(f"[dim]Report written to {args.output}[/dim]")
    except OSError as error:
        console.print(f"[yellow]WARN: could not write {args.output}: {error}[/yellow]")

    if args.no_datahub:
        console.print("[yellow][DRY RUN] DataHub write-back skipped[/yellow]")
    else:
        result = write_assets_to_datahub(assets, url=args.url, token=args.token)
        console.print(f"[dim]DataHub: {result['written']} written, {result['failed']} failed[/dim]")
        build_lineage(assets, url=args.url, token=args.token)

    if summary["critical_count"]:
        console.print()
        console.print(_critical_panel(assets))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
