"""Tests for risk propagation across the lineage graph.

Run: python3 tests/test_propagation.py   (or: pytest tests/test_propagation.py)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.risk.propagation import propagate  # noqa: E402


def _server(name, tools, score, tier, poisoned=False):
    return {
        "type": "mcp_server",
        "name": name,
        "url": f"http://127.0.0.1:31{abs(hash(name)) % 90:02d}",
        "tools": tools,
        "risk_score": score,
        "risk_tier": tier,
        "poison": {"poisoned": poisoned, "findings": [{"kind": "x"}] if poisoned else []},
    }


GHOST = _server("Ghost MCP", ["exec_shell", "spawn_agent", "list_secrets"], 100, "critical", True)
QUIET = _server("Mistral Local Agent", ["chat"], 40, "medium")
FILES = _server("Claude MCP", ["read_file", "search_codebase"], 44, "medium")
AGENT = {"type": "agent", "name": "claude", "command": "claude", "risk_score": 0, "risk_tier": "low"}


def _config(tmp, *servers):
    path = os.path.join(tmp, ".mcp.json")
    with open(path, "w") as handle:
        json.dump({"mcpServers": {s["name"]: {"url": s["url"], "tools": s["tools"]}
                                  for s in servers}}, handle)
    return path


def test_agent_inherits_worst_connected_server():
    with tempfile.TemporaryDirectory() as tmp:
        path = _config(tmp, GHOST, QUIET)
        assets = propagate([dict(GHOST), dict(QUIET), dict(AGENT)], mcp_config_paths=[path])

    agent = next(a for a in assets if a["type"] == "agent")
    assert agent["risk_score"] == 100, agent
    assert agent["risk_tier"] == "critical"
    prop = agent["propagation"]
    assert prop["inherited_score"] == 100
    assert "Ghost MCP" in prop["inherited_from"]


def test_agent_is_flagged_when_an_upstream_server_is_poisoned():
    with tempfile.TemporaryDirectory() as tmp:
        path = _config(tmp, GHOST)
        assets = propagate([dict(GHOST), dict(AGENT)], mcp_config_paths=[path])

    agent = next(a for a in assets if a["type"] == "agent")
    assert agent["propagation"]["poisoned_upstream"] is True


def test_agent_without_connections_is_untouched():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "empty.json")
        with open(path, "w") as handle:
            json.dump({"mcpServers": {}}, handle)
        assets = propagate([dict(QUIET), dict(AGENT)], mcp_config_paths=[path])

    agent = next(a for a in assets if a["type"] == "agent")
    assert agent["risk_score"] == 0
    assert agent["propagation"]["inherited_from"] == []


def test_propagation_never_lowers_an_existing_score():
    hot_agent = dict(AGENT, risk_score=90, risk_tier="critical")
    with tempfile.TemporaryDirectory() as tmp:
        path = _config(tmp, QUIET)
        assets = propagate([dict(QUIET), hot_agent], mcp_config_paths=[path])

    agent = next(a for a in assets if a["type"] == "agent")
    assert agent["risk_score"] == 90


def test_spawning_server_blast_radius_covers_the_whole_agent_config():
    """A spawned child inherits the parent agent's config, so the real blast
    radius of a server that can spawn is every source the fleet can reach."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _config(tmp, GHOST, FILES)
        assets = propagate([dict(GHOST), dict(FILES), dict(AGENT)], mcp_config_paths=[path])

    ghost = next(a for a in assets if a["name"] == "Ghost MCP")
    prop = ghost["propagation"]
    assert prop["spawns_agents"] is True
    direct = set(prop["direct_data_sources"])
    effective = set(prop["effective_data_sources"])
    assert direct < effective, (direct, effective)
    assert "Filesystem" in effective, effective


def test_server_without_spawn_capability_does_not_amplify():
    with tempfile.TemporaryDirectory() as tmp:
        path = _config(tmp, GHOST, FILES)
        assets = propagate([dict(GHOST), dict(FILES), dict(AGENT)], mcp_config_paths=[path])

    files = next(a for a in assets if a["name"] == "Claude MCP")
    prop = files["propagation"]
    assert prop["spawns_agents"] is False
    assert set(prop["effective_data_sources"]) == set(prop["direct_data_sources"])


if __name__ == "__main__":
    failed = 0
    for name, fn in sorted(globals().items()):
        if not name.startswith("test_") or not callable(fn):
            continue
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as error:
            failed += 1
            print(f"  FAIL  {name}: {error}")
        except Exception as error:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {name}: {type(error).__name__}: {error}")
    print(f"\n{failed} failed")
    sys.exit(1 if failed else 0)
