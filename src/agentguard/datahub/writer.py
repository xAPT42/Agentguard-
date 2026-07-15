"""Write-back of the discovered agent fleet to DataHub."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

try:
    from datahub.emitter.mcp import MetadataChangeProposalWrapper
    from datahub.emitter.rest_emitter import DatahubRestEmitter
    from datahub.metadata.schema_classes import (
        GlobalTagsClass,
        MLModelPropertiesClass,
        OwnerClass,
        OwnershipClass,
        OwnershipTypeClass,
        TagAssociationClass,
    )

    DATAHUB_AVAILABLE = True
except ImportError:
    DATAHUB_AVAILABLE = False

DEFAULT_DATAHUB_URL = "http://localhost:8080"
DEFAULT_OWNER = "urn:li:corpuser:admin"
PLATFORM = "mcp"

EU_AI_ACT_RISK_CATEGORY = {
    "critical": "high-risk",
    "high": "high-risk",
    "medium": "limited-risk",
    "low": "minimal-risk",
}

HUMAN_CHANNEL_KEYWORDS = (
    "email",
    "mail",
    "chat",
    "message",
    "notify",
    "reply",
    "comment",
    "sms",
    "slack",
    "publish",
    "respond",
)


def _normalize(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(name)).strip("-").lower() or "unknown"


def build_urn(asset: dict[str, Any]) -> str:
    """Return the DataHub mlModel URN for an asset."""
    return f"urn:li:mlModel:(urn:li:dataPlatform:{PLATFORM},{_normalize(asset.get('name', 'unknown'))},PROD)"


def _data_access_scope(asset: dict[str, Any]) -> str:
    tools = [str(tool).lower() for tool in asset.get("tools") or []]
    if not tools:
        return "unknown"
    scopes = []
    if any(word in tool for tool in tools for word in ("file", "fs", "read_file")):
        scopes.append("filesystem")
    if any(word in tool for tool in tools for word in ("db", "sql", "database", "query")):
        scopes.append("database")
    if any(word in tool for tool in tools for word in ("http", "web", "fetch", "url")):
        scopes.append("network")
    if any(word in tool for tool in tools for word in ("shell", "exec", "cmd", "bash")):
        scopes.append("system")
    return ",".join(scopes) if scopes else "application"


def _disclosure_compliant(asset: dict[str, Any]) -> str:
    """Assess Art. 50 transparency: only assets that address humans carry the obligation."""
    if "disclosure_declared" in asset:
        return "true" if asset["disclosure_declared"] else "false"

    tools = [str(tool).lower() for tool in asset.get("tools") or []]
    addresses_humans = any(word in tool for tool in tools for word in HUMAN_CHANNEL_KEYWORDS)
    if not addresses_humans:
        return "not_applicable"
    return "false"


def _custom_properties(asset: dict[str, Any]) -> dict[str, str]:
    tier = str(asset.get("risk_tier", "low"))
    security = asset.get("security") or {}
    requires_auth = bool(security.get("requires_auth", False))

    return {
        "agentguard.risk_score": str(asset.get("risk_score", 0)),
        "agentguard.risk_tier": tier,
        "agentguard.status": str(asset.get("status", "UNKNOWN")),
        "agentguard.requires_auth": str(requires_auth).lower(),
        "agentguard.eu_ai_act.owner": str(asset.get("owner", DEFAULT_OWNER)),
        "agentguard.eu_ai_act.data_access_scope": _data_access_scope(asset),
        "agentguard.eu_ai_act.disclosure_compliant": _disclosure_compliant(asset),
        "agentguard.eu_ai_act.risk_category": EU_AI_ACT_RISK_CATEGORY.get(tier, "minimal-risk"),
        "agentguard.owasp_tags": ",".join(asset.get("owasp_tags") or []),
        "agentguard.last_seen": datetime.now(timezone.utc).isoformat(),
    }


def _tags(asset: dict[str, Any]) -> list[str]:
    tags = ["agentguard-discovered", f"risk-{asset.get('risk_tier', 'low')}"]
    if str(asset.get("status", "")).upper() == "ORPHANED":
        tags.append("orphaned")
    tags.extend(asset.get("owasp_tags") or [])
    return tags


def _aspects(asset: dict[str, Any]) -> list[Any]:
    description = (
        f"{asset.get('type', 'asset')} discovered by AgentGuard via "
        f"{asset.get('discovered_via') or asset.get('source', 'scan')}"
    )

    return [
        MLModelPropertiesClass(
            name=str(asset.get("name", "unknown")),
            description=description,
            customProperties=_custom_properties(asset),
            externalUrl=asset.get("url") or None,
        ),
        GlobalTagsClass(
            tags=[TagAssociationClass(tag=f"urn:li:tag:{tag}") for tag in _tags(asset)]
        ),
        OwnershipClass(
            owners=[
                OwnerClass(owner=DEFAULT_OWNER, type=OwnershipTypeClass.TECHNICAL_OWNER)
            ]
        ),
    ]


def write_assets_to_datahub(
    assets: list[dict[str, Any]],
    url: str | None = None,
    token: str | None = None,
) -> dict[str, int]:
    """Emit each asset to DataHub as an mlModel. Never raises on connection failure."""
    result = {"written": 0, "failed": 0}
    if not assets:
        return result

    if not DATAHUB_AVAILABLE:
        print("WARN: acryl-datahub is not installed, skipping DataHub write-back")
        result["failed"] = len(assets)
        return result

    gms_url = url or os.environ.get("DATAHUB_URL", DEFAULT_DATAHUB_URL)
    gms_token = token or os.environ.get("DATAHUB_TOKEN")

    try:
        emitter = DatahubRestEmitter(gms_server=gms_url, token=gms_token)
        emitter.test_connection()
    except Exception as error:
        print(f"WARN: DataHub unreachable at {gms_url} ({error}); skipping write-back")
        result["failed"] = len(assets)
        return result

    for asset in assets:
        urn = build_urn(asset)
        try:
            for aspect in _aspects(asset):
                emitter.emit(MetadataChangeProposalWrapper(entityUrn=urn, aspect=aspect))
            result["written"] += 1
        except Exception as error:
            print(f"WARN: failed to write {urn}: {error}")
            result["failed"] += 1

    return result
