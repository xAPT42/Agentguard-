"""Tests for lineage edge detection.

Run: python3 tests/test_lineage.py   (or: pytest tests/test_lineage.py)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.datahub.lineage import _edges, _server_datasets  # noqa: E402

# Mirrors the real scanner output: mcp_server assets carry only name/url/tools,
# agent assets carry only name/command. They share no field.
FLEET = [
    {
        "type": "mcp_server",
        "name": "LangChain Agent",
        "url": "http://127.0.0.1:3100",
        "tools": ["run_shell", "http_fetch", "write_report", "read_file", "search_index", "send_email"],
    },
    {
        "type": "mcp_server",
        "name": "Ghost MCP",
        "url": "http://127.0.0.1:3101",
        "tools": ["exec_shell", "send_email", "spawn_agent", "list_secrets", "delete_file"],
    },
    {
        "type": "mcp_server",
        "name": "Qdrant Search",
        "url": "http://127.0.0.1:3106",
        "tools": ["search", "upsert"],
    },
    {
        "type": "mcp_server",
        "name": "DataHub MCP",
        "url": "http://127.0.0.1:3108",
        "tools": ["get_dataset", "get_lineage"],
    },
    {"type": "agent", "name": "claude", "command": "claude"},
]


def test_server_datasets_maps_tool_verbs_to_data_sources():
    """Real MCP tools are verbs (exec_shell), never platform names (postgres)."""
    urns = _server_datasets(FLEET[1])  # Ghost MCP
    assert urns, "Ghost MCP exposes exec_shell/list_secrets but yielded no data sources"
    joined = " ".join(urns)
    for expected in ("os-shell", "secrets-store", "email", "filesystem", "agent-network"):
        assert expected in joined, f"missing {expected!r} in {urns}"


def test_server_with_no_data_reaching_tools_yields_nothing():
    quiet = {"type": "mcp_server", "name": "Mistral Local Agent", "tools": ["chat", "function_call"]}
    assert _server_datasets(quiet) == []


def test_edges_are_produced_for_a_realistic_fleet():
    edges = _edges(FLEET)
    assert edges, "no lineage edges from a fleet that clearly touches shell, secrets and email"


def test_agent_connects_to_servers_declared_in_mcp_config():
    """The MCP client config is the ground truth for agent -> server edges."""
    config = {
        "mcpServers": {
            "Ghost MCP": {"url": "http://127.0.0.1:3101", "tools": []},
            "Qdrant Search": {"url": "http://127.0.0.1:3106", "tools": []},
        }
    }
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, ".mcp.json")
        with open(path, "w") as handle:
            json.dump(config, handle)
        edges = _edges(FLEET, mcp_config_paths=[path])

    agent_edges = [e for e in edges if ":mlModel:" in e[0]]
    assert agent_edges, "agent 'claude' declares 2 servers in .mcp.json but produced no edge"
    upstreams = " ".join(u for _, ups in agent_edges for u in ups)
    assert "ghost-mcp" in upstreams
    assert "qdrant-search" in upstreams


def test_dataset_urns_are_well_formed():
    for urn in _server_datasets(FLEET[0]):
        assert urn.startswith("urn:li:dataset:(urn:li:dataPlatform:"), urn
        assert urn.endswith(",PROD)"), urn


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
