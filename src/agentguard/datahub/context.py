"""Read the catalog through DataHub's MCP Server before writing to it.

A scanner that only writes has no memory: every run reports ten assets and
cannot say which of them are new. DataHub already knows what was there last
time, so AgentGuard asks it - through the MCP Server, the same interface an
agent would use - which of the assets it just discovered are already
catalogued, and what each one is connected to.

That makes the catalog the source of truth for fleet drift rather than a local
state file, and it is what lets the next run, or the next person, inherit what
this one found.
"""

from __future__ import annotations

import os
from typing import Any

from agentguard.datahub.lineage import _job_urn
from agentguard.datahub.writer import build_urn
from agentguard.scanner.mcp_session import McpSession

DEFAULT_MCP_URL = "http://127.0.0.1:8888/mcp"


def _entity_exists(session: McpSession, urn: str) -> bool:
    result = session.call_tool("get_entities", {"urns": [urn]})
    if isinstance(result, dict):
        entities = result.get("entities") or result.get("results") or []
        if isinstance(entities, list):
            return bool(entities)
        return bool(entities)
    if isinstance(result, list):
        return bool(result)
    return False


def _lineage_count(session: McpSession, asset: dict[str, Any]) -> int | None:
    """How many entities this asset connects to, according to the catalog.

    Lineage hangs off the dataJob for a server, not off its mlModel, so the
    URN to ask about depends on the asset type. The server nests the answer
    under upstreams/downstreams rather than returning a flat total.
    """
    is_server = asset.get("type") == "mcp_server"
    urn = _job_urn(asset) if is_server else build_urn(asset)
    # A server's connections sit upstream of its dataJob; an agent's hang off
    # its mlModel as downstreamJobs.
    result = session.call_tool(
        "get_lineage",
        {"urn": urn, "upstream": is_server, "max_hops": 1, "max_results": 50},
    )
    if not isinstance(result, dict):
        return None
    for key in ("upstreams", "downstreams"):
        block = result.get(key)
        if isinstance(block, dict) and isinstance(block.get("total"), int):
            return block["total"]
    return None


def read_catalog_context(
    assets: list[dict[str, Any]],
    mcp_url: str | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Mark each asset as already catalogued or new, using the MCP Server.

    Returns a summary. Failure is not fatal: an unreachable MCP Server leaves
    every asset unmarked rather than claiming they are all new, because "we
    could not ask" and "it is not there" are different answers.
    """
    url = mcp_url or os.environ.get("DATAHUB_MCP_URL", DEFAULT_MCP_URL)
    key = token if token is not None else os.environ.get("DATAHUB_GMS_TOKEN")

    session = McpSession(url, timeout=15.0, token=key)
    if not session.open():
        return {"available": False, "reason": f"MCP Server unreachable at {url}"}

    known = new = 0
    for asset in assets:
        urn = build_urn(asset)
        exists = _entity_exists(session, urn)
        asset["catalog"] = {"urn": urn, "known": exists}
        if exists:
            known += 1
            connections = _lineage_count(session, asset)
            if connections is not None:
                asset["catalog"]["connections"] = connections
        else:
            new += 1

    return {
        "available": True,
        "url": url,
        "tools_used": ["get_entities", "get_lineage"],
        "already_catalogued": known,
        "new_since_last_scan": new,
    }
