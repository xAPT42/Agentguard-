"""Lineage emission: agent -> mcp_server -> dataset.

DataHub models this chain with three entity types:

    mlModel (agent)  --downstreamJobs-->  dataJob (mcp server)  --inputDatasets-->  dataset

`upstreamLineage` is a *dataset* aspect and is rejected on mlModel URNs
("Unknown aspect upstreamLineage for entity mlModel", HTTP 422), so the agent
and server sides go through dataJob instead.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

try:
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.emitter.rest_emitter import DatahubRestEmitter
    from datahub.metadata.schema_classes import (
        DataFlowInfoClass,
        DataJobInfoClass,
        DataJobInputOutputClass,
        DatasetPropertiesClass,
    )

    DATAHUB_AVAILABLE = True
except ImportError:
    DATAHUB_AVAILABLE = False

from agentguard.datahub.writer import DEFAULT_DATAHUB_URL, PLATFORM, build_urn

FLOW_URN = "urn:li:dataFlow:(agentguard,agent-fleet,PROD)"

# Where MCP clients declare the servers they talk to. This is the ground truth
# for agent -> server edges: a discovered agent and a discovered server share no
# field the scanner can match on (servers expose name/url/tools over HTTP,
# agents expose a command line), so the client config is the only real link.
DEFAULT_MCP_CONFIG_PATHS = (
    ".mcp.json",
    os.path.expanduser("~/.claude.json"),
    os.path.expanduser("~/.cursor/mcp.json"),
)

# Tool verbs -> the data source they reach. Real MCP tools are named for what
# they do (`exec_shell`, `list_secrets`), never for the platform behind them,
# so matching on storage-platform names alone finds nothing.
# Kept in sync with the KW map in dashboard/index.html (renderBlastRadius).
TOOL_DATA_SOURCES: tuple[tuple[str, str, str], ...] = (
    # keyword, data source label, DataHub platform
    ("shell", "OS Shell", "system"),
    ("exec", "OS Shell", "system"),
    ("secret", "Secrets Store", "vault"),
    ("credential", "Secrets Store", "vault"),
    ("directory", "Filesystem", "file"),
    ("file", "Filesystem", "file"),
    ("email", "Email", "smtp"),
    ("mail", "Email", "smtp"),
    ("message", "Messaging", "messaging"),
    ("spawn", "Agent Network", "agentguard"),
    ("database", "SQL Database", "sql"),
    ("query", "SQL Database", "sql"),
    ("sql", "SQL Database", "sql"),
    ("db", "SQL Database", "sql"),
    ("search", "Search Index", "elasticsearch"),
    ("index", "Search Index", "elasticsearch"),
    ("vector", "Vector Store", "vectordb"),
    ("embedding", "Vector Store", "vectordb"),
    ("upsert", "Vector Store", "vectordb"),
    ("collection", "Vector Store", "vectordb"),
    ("dataset", "DataHub", "datahub"),
    ("lineage", "DataHub", "datahub"),
    ("metadata", "DataHub", "datahub"),
    ("report", "Reports", "file"),
    ("export", "Reports", "file"),
    ("http", "External API", "http"),
    ("fetch", "External API", "http"),
)


def _normalize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(name)).strip("-").lower()


def _dataset_urn(platform: str, label: str) -> str:
    return f"urn:li:dataset:(urn:li:dataPlatform:{platform},{_normalize(label)},PROD)"


def _job_urn(server: dict[str, Any]) -> str:
    return f"urn:li:dataJob:({FLOW_URN},{_normalize(server.get('name', 'unknown'))})"


def _data_sources(server: dict[str, Any]) -> dict[str, str]:
    """Data source label -> DataHub platform, for this server's tools."""
    tools = [str(tool).lower() for tool in server.get("tools") or []]
    found: dict[str, str] = {}
    for tool in tools:
        for keyword, label, platform in TOOL_DATA_SOURCES:
            if keyword in tool:
                found[label] = platform
    return found


def data_source_labels(server: dict[str, Any]) -> list[str]:
    """Human-readable data sources a server's tools can reach."""
    return sorted(_data_sources(server))


def _server_datasets(server: dict[str, Any]) -> list[str]:
    """Dataset URNs for every data source this server's tools can reach."""
    return [_dataset_urn(platform, label) for label, platform in sorted(_data_sources(server).items())]


def agent_server_links(
    assets: list[dict[str, Any]], mcp_config_paths: list[str] | None = None
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Each agent paired with the servers it actually talks to."""
    agents = [a for a in assets if a.get("type") == "agent"]
    servers = [a for a in assets if a.get("type") == "mcp_server"]
    declared = _declared_servers(mcp_config_paths)
    return [
        (agent, [s for s in servers if _agent_connects_to(agent, s, declared)])
        for agent in agents
    ]


def _declared_servers(paths: list[str] | None = None) -> set[str]:
    """Server names and URLs declared in any reachable MCP client config."""
    declared: set[str] = set()
    for path in paths if paths is not None else DEFAULT_MCP_CONFIG_PATHS:
        try:
            with open(path) as handle:
                config = json.load(handle)
        except (OSError, ValueError):
            continue
        for name, entry in (config.get("mcpServers") or {}).items():
            declared.add(str(name).lower())
            url = (entry or {}).get("url")
            if url:
                declared.add(str(url).lower())
    return declared


def _agent_connects_to(
    agent: dict[str, Any], server: dict[str, Any], declared: set[str]
) -> bool:
    server_name = str(server.get("name", "")).lower()
    server_url = str(server.get("url", "")).lower()
    if not server_name:
        return False

    # The MCP client config is host/project scoped: a server listed there is one
    # the agents on this host actually talk to.
    if server_name in declared or (server_url and server_url in declared):
        return True

    haystack = " ".join(
        str(agent.get(field, "")).lower()
        for field in ("command", "image", "name", "env_path")
    )
    return server_name in haystack or bool(server_url) and server_url in haystack


def _edges(
    assets: list[dict[str, Any]], mcp_config_paths: list[str] | None = None
) -> list[tuple[str, list[str]]]:
    """(downstream_urn, upstream_urns) for agent->server and server->dataset."""
    servers = [a for a in assets if a.get("type") == "mcp_server"]
    edges: list[tuple[str, list[str]]] = []

    for agent, connected in agent_server_links(assets, mcp_config_paths):
        if connected:
            edges.append((build_urn(agent), [build_urn(s) for s in connected]))

    for server in servers:
        datasets = _server_datasets(server)
        if datasets:
            edges.append((build_urn(server), datasets))

    return edges


def attach_downstream_jobs(
    assets: list[dict[str, Any]], mcp_config_paths: list[str] | None = None
) -> list[dict[str, Any]]:
    """Record, on each agent, the dataJobs for the servers it talks to.

    The writer folds this into the single MLModelProperties aspect it emits.
    Emitting a second, thinner aspect here would silently replace the first:
    DataHub upserts a non-timeseries aspect as a whole value, it does not merge.
    """
    for agent, servers in agent_server_links(assets, mcp_config_paths):
        agent["downstream_jobs"] = [_job_urn(server) for server in servers]
    return assets


def build_lineage(
    assets: list[dict[str, Any]],
    url: str | None = None,
    token: str | None = None,
    mcp_config_paths: list[str] | None = None,
) -> None:
    """Emit the agent -> mcp_server -> dataset chain into DataHub."""
    if not DATAHUB_AVAILABLE:
        print("WARN: acryl-datahub is not installed, skipping lineage")
        return

    edges = _edges(assets, mcp_config_paths)
    if not edges:
        print("INFO: no agent/server connections detected, skipping lineage")
        return

    gms_url = url or os.environ.get("DATAHUB_URL", DEFAULT_DATAHUB_URL)
    gms_token = token or os.environ.get("DATAHUB_TOKEN")

    try:
        emitter = DatahubRestEmitter(gms_server=gms_url, token=gms_token)
        emitter.test_connection()
    except Exception as error:
        print(f"WARN: DataHub unreachable at {gms_url} ({error}); skipping lineage")
        return

    servers = {build_urn(a): a for a in assets if a.get("type") == "mcp_server"}
    emitted = 0
    failures = 0

    def emit(urn: str, aspect: Any) -> bool:
        nonlocal failures
        try:
            emitter.emit(MetadataChangeProposalWrapper(entityUrn=urn, aspect=aspect))
            return True
        except Exception as error:
            failures += 1
            print(f"WARN: failed to emit for {urn}: {error}")
            return False

    # The flow every MCP server hangs off of.
    emit(FLOW_URN, DataFlowInfoClass(name="AgentGuard fleet"))

    for downstream_urn, upstream_urns in edges:
        server = servers.get(downstream_urn)

        if server is not None:
            # server -> datasets, as a dataJob reading each data source.
            job_urn = _job_urn(server)
            for dataset_urn in upstream_urns:
                label = dataset_urn.split(",")[1]
                emit(dataset_urn, DatasetPropertiesClass(name=label))
            emit(
                job_urn,
                DataJobInfoClass(name=str(server.get("name", "unknown")), type="COMMAND"),
            )
            if emit(job_urn, DataJobInputOutputClass(inputDatasets=list(upstream_urns), outputDatasets=[])):
                emitted += len(upstream_urns)
        else:
            # agent -> servers: carried by MLModelProperties.downstreamJobs,
            # which the writer emits as part of the asset's single aspect.
            emitted += sum(1 for urn in upstream_urns if urn in servers)

    suffix = f", {failures} failed" if failures else ""
    print(f"INFO: emitted {emitted} lineage edge(s){suffix}")
