"""AgentGuard command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from agentguard import __version__
from agentguard.datahub.lineage import build_lineage
from agentguard.datahub.skill import summarize
from agentguard.datahub.writer import write_assets_to_datahub
from agentguard.risk.scorer import score_assets
from agentguard.scanner.agent_scanner import scan_agents
from agentguard.scanner.mcp_scanner import scan_mcp_servers

DEFAULT_OUTPUT = "scan_output.json"
COLUMNS = ("NAME", "TYPE", "STATUS", "RISK", "TIER")


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


def _print_table(assets: list[dict[str, Any]]) -> None:
    rows = [
        (
            str(asset.get("name", "unknown")),
            str(asset.get("type", "unknown")),
            str(asset.get("status", "UNKNOWN")),
            str(asset.get("risk_score", 0)),
            str(asset.get("risk_tier", "low")),
        )
        for asset in assets
    ]

    widths = [
        max(len(COLUMNS[index]), max((len(row[index]) for row in rows), default=0))
        for index in range(len(COLUMNS))
    ]
    separator = "-+-".join("-" * width for width in widths)

    print(" | ".join(column.ljust(widths[index]) for index, column in enumerate(COLUMNS)))
    print(separator)
    for row in rows:
        print(" | ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def _print_summary(summary: dict[str, Any]) -> None:
    tiers = summary["by_risk_tier"]
    breakdown = ", ".join(f"{tier}: {count}" for tier, count in sorted(tiers.items())) or "none"
    print(f"\n{summary['total']} asset(s) discovered — {breakdown}")


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    print("Scanning for MCP servers and AI agents...")
    assets = score_assets(scan_mcp_servers() + scan_agents())

    if not assets:
        print("No AI agents or MCP servers found.")
        return 0

    assets.sort(key=lambda asset: asset.get("risk_score", 0), reverse=True)
    _print_table(assets)

    summary = summarize(assets)
    _print_summary(summary)

    report = {"version": __version__, "summary": summary, "assets": assets}
    try:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"Report written to {args.output}")
    except OSError as error:
        print(f"WARN: could not write {args.output}: {error}")

    if args.no_datahub:
        print("Dry run: skipping DataHub write-back.")
    else:
        result = write_assets_to_datahub(assets, url=args.url, token=args.token)
        print(f"DataHub: {result['written']} written, {result['failed']} failed")
        build_lineage(assets, url=args.url, token=args.token)

    if summary["critical_count"]:
        print(f"\nFAIL: {summary['critical_count']} critical asset(s) require attention.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
