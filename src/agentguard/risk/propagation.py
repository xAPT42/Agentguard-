"""Risk propagation across the agent -> server -> data source graph.

Scoring each asset alone misses how the fleet actually fails. Two effects:

An agent is only as contained as the worst server it talks to. Our own scan
scored the `claude` agent 0 while it was wired to a poisoned server holding
exec_shell and reachable credentials -- the agent is the thing that runs the
injected instruction, so the exposure is its own.

A server that can spawn agents does not stop at the data it touches. The child
inherits the parent agent's configuration, so it reaches every server in that
config. The blast radius of a spawning server is the whole fleet's reach, not
its own tool list.
"""

from __future__ import annotations

from typing import Any

from agentguard.datahub.lineage import agent_server_links, data_source_labels
from agentguard.risk.scorer import _risk_tier as risk_tier

SPAWN_KEYWORDS = ("spawn", "create_agent", "delegate", "subagent", "child_agent")


def _spawns_agents(server: dict[str, Any]) -> bool:
    tools = [str(tool).lower() for tool in server.get("tools") or []]
    return any(keyword in tool for tool in tools for keyword in SPAWN_KEYWORDS)


def propagate(
    assets: list[dict[str, Any]], mcp_config_paths: list[str] | None = None
) -> list[dict[str, Any]]:
    """Annotate assets with inherited risk and effective blast radius."""
    links = agent_server_links(assets, mcp_config_paths)

    # Baseline: a server reaches what its own tools reach.
    for server in assets:
        if server.get("type") != "mcp_server":
            continue
        direct = data_source_labels(server)
        server["propagation"] = {
            "spawns_agents": _spawns_agents(server),
            "direct_data_sources": direct,
            "effective_data_sources": direct,
            "amplification": 0,
            "reached_via_agents": [],
        }

    for agent, servers in links:
        scores = [(int(s.get("risk_score") or 0), str(s.get("name", "?"))) for s in servers]
        inherited = max((score for score, _ in scores), default=0)
        worst = sorted(name for score, name in scores if score == inherited) if scores else []

        agent["propagation"] = {
            "inherited_score": inherited,
            "inherited_from": worst if inherited else [],
            "connected_servers": sorted(str(s.get("name", "?")) for s in servers),
            "poisoned_upstream": any(
                (s.get("poison") or {}).get("poisoned") for s in servers
            ),
        }

        if inherited > int(agent.get("risk_score") or 0):
            agent["risk_score"] = inherited
            agent["risk_tier"] = risk_tier(inherited)

        # Everything this agent can reach is what a spawned child inherits.
        fleet_sources = sorted(
            {label for server in servers for label in data_source_labels(server)}
        )
        for server in servers:
            propagation = server["propagation"]
            propagation["reached_via_agents"] = sorted(
                set(propagation["reached_via_agents"]) | {str(agent.get("name", "?"))}
            )
            if not propagation["spawns_agents"]:
                continue
            effective = sorted(set(propagation["effective_data_sources"]) | set(fleet_sources))
            propagation["effective_data_sources"] = effective
            propagation["amplification"] = len(effective) - len(
                propagation["direct_data_sources"]
            )

    return assets
