"""Lineage emission: agent -> mcp_server -> dataset."""

from __future__ import annotations

import os
import re
from typing import Any

try:
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.emitter.rest_emitter import DatahubRestEmitter
    from datahub.metadata.schema_classes import (
        DatasetLineageTypeClass,
        UpstreamClass,
        UpstreamLineageClass,
    )

    DATAHUB_AVAILABLE = True
except ImportError:
    DATAHUB_AVAILABLE = False

from agentguard.datahub.writer import DEFAULT_DATAHUB_URL, build_urn

DATASET_KEYWORDS = {
    "postgres": "postgres",
    "mysql": "mysql",
    "snowflake": "snowflake",
    "bigquery": "bigquery",
    "s3": "s3",
    "kafka": "kafka",
    "mongo": "mongodb",
}


def _normalize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(name)).strip("-").lower()


def _dataset_urn(platform: str, name: str) -> str:
    return f"urn:li:dataset:(urn:li:dataPlatform:{platform},{_normalize(name)},PROD)"


def _agent_connects_to(agent: dict[str, Any], server: dict[str, Any]) -> bool:
    server_name = str(server.get("name", "")).lower()
    if not server_name:
        return False

    haystack = " ".join(
        str(agent.get(field, "")).lower()
        for field in ("command", "image", "name", "env_path")
    )
    if server_name in haystack:
        return True

    url = str(server.get("url", ""))
    return bool(url) and url in haystack


def _server_datasets(server: dict[str, Any]) -> list[str]:
    tools = " ".join(str(tool).lower() for tool in server.get("tools") or [])
    urns = []
    for keyword, platform in DATASET_KEYWORDS.items():
        if keyword in tools:
            urns.append(_dataset_urn(platform, f"{_normalize(server.get('name', 'unknown'))}.data"))
    return urns


def _upstream(urn: str) -> Any:
    return UpstreamClass(dataset=urn, type=DatasetLineageTypeClass.TRANSFORMED)


def _edges(assets: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    agents = [a for a in assets if a.get("type") == "agent"]
    servers = [a for a in assets if a.get("type") == "mcp_server"]

    edges: list[tuple[str, list[str]]] = []

    for agent in agents:
        upstreams = [build_urn(server) for server in servers if _agent_connects_to(agent, server)]
        if upstreams:
            edges.append((build_urn(agent), upstreams))

    for server in servers:
        datasets = _server_datasets(server)
        if datasets:
            edges.append((build_urn(server), datasets))

    return edges


def build_lineage(
    assets: list[dict[str, Any]],
    url: str | None = None,
    token: str | None = None,
) -> None:
    """Emit UpstreamLineage aspects for every detectable agent/server/dataset connection."""
    if not DATAHUB_AVAILABLE:
        print("WARN: acryl-datahub is not installed, skipping lineage")
        return

    edges = _edges(assets)
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

    emitted = 0
    for downstream_urn, upstream_urns in edges:
        aspect = UpstreamLineageClass(upstreams=[_upstream(urn) for urn in upstream_urns])
        try:
            emitter.emit(MetadataChangeProposalWrapper(entityUrn=downstream_urn, aspect=aspect))
            emitted += 1
        except Exception as error:
            print(f"WARN: failed to emit lineage for {downstream_urn}: {error}")

    print(f"INFO: emitted {emitted} lineage edge(s)")
