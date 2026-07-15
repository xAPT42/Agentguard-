"""AgentGuard packaged as a reusable DataHub agent skill."""

from __future__ import annotations

from typing import Any

from agentguard.datahub.lineage import build_lineage
from agentguard.datahub.writer import write_assets_to_datahub
from agentguard.risk.scorer import score_assets
from agentguard.scanner.agent_scanner import scan_agents
from agentguard.scanner.mcp_scanner import scan_mcp_servers


class AgentGuardSkill:
    """Scan, score, and publish an AI agent fleet to DataHub."""

    name = "agentguard"
    description = (
        "Scan and inventory all AI agents and MCP servers, score their risk, write to DataHub"
    )

    def run(self, context: Any = None) -> dict[str, Any]:
        """Execute the discovery pipeline and return a fleet summary."""
        options = _as_dict(context)
        url = options.get("url")
        token = options.get("token")
        write_enabled = options.get("write_to_datahub", True)

        assets = score_assets(scan_mcp_servers() + scan_agents())

        emitted = {"written": 0, "failed": 0}
        if write_enabled:
            emitted = write_assets_to_datahub(assets, url=url, token=token)
            build_lineage(assets, url=url, token=token)

        return {
            "skill": self.name,
            "assets": assets,
            "summary": summarize(assets),
            "datahub": emitted,
        }


def summarize(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Return fleet-level counts by tier and status."""
    tiers: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for asset in assets:
        tier = str(asset.get("risk_tier", "low"))
        status = str(asset.get("status", "UNKNOWN"))
        tiers[tier] = tiers.get(tier, 0) + 1
        statuses[status] = statuses.get(status, 0) + 1

    return {
        "total": len(assets),
        "by_risk_tier": tiers,
        "by_status": statuses,
        "critical_count": tiers.get("critical", 0),
    }


def _as_dict(context: Any) -> dict[str, Any]:
    if context is None:
        return {}
    if isinstance(context, dict):
        return context
    return {
        key: getattr(context, key)
        for key in ("url", "token", "write_to_datahub")
        if hasattr(context, key)
    }
