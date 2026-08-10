"""Risk scoring with OWASP LLM Top 10 tagging."""

from __future__ import annotations

from typing import Any

POISONED_TOOL_POINTS = 45
CONFIG_DRIFT_POINTS = 20
NO_AUTH_POINTS = 40
MUTATING_TOOL_POINTS = 25
SHELL_TOOL_POINTS = 20
ORPHANED_POINTS = 20
TOOL_SPRAWL_POINTS = 10
UNKNOWN_POINTS = 10
CREDENTIAL_POINTS = 10
READ_TOOL_POINTS = 4

TOOL_SPRAWL_THRESHOLD = 5
MAX_SCORE = 100

TIERS = [(75, "critical"), (50, "high"), (25, "medium")]

MUTATING_KEYWORDS = ("write", "delete", "exec", "create", "update", "drop", "remove", "put", "post")
SHELL_KEYWORDS = ("shell", "cmd", "command", "bash", "terminal", "subprocess")
READ_KEYWORDS = ("file", "read", "db", "database", "query", "sql", "fetch", "get", "list", "search")

# OWASP GenAI LLM Top 10 2026 (published 2026-08-04). The 2023 edition, which
# numbered Sensitive Information Disclosure LLM06 and Excessive Agency LLM08,
# is marked a historical archive by OWASP.
OWASP_LABELS = {
    "LLM01": "LLM01: Prompt Injection",
    "LLM02": "LLM02: Sensitive Information Disclosure",
    "LLM03": "LLM03: Excessive Agency",
    "MCP03": "MCP03: Tool Poisoning",
    "LLM04": "LLM04: Supply Chain",
}


def _tools(asset: dict[str, Any]) -> list[str]:
    tools = asset.get("tools") or []
    return [str(tool).lower() for tool in tools]


def _matches(tools: list[str], keywords: tuple[str, ...]) -> bool:
    return any(keyword in tool for tool in tools for keyword in keywords)


def _requires_auth(asset: dict[str, Any]) -> bool:
    """Whether the asset demands credentials from callers reaching it."""
    security = asset.get("security") or {}
    return bool(security.get("requires_auth", False))


def _is_exposed(asset: dict[str, Any]) -> bool:
    """Whether the asset accepts inbound connections, making auth meaningful."""
    if asset.get("type") == "mcp_server":
        return True
    return str(asset.get("url") or "").startswith("http")


def _holds_credentials(asset: dict[str, Any]) -> bool:
    """Whether the asset carries outbound API credentials in its environment."""
    return bool(asset.get("api_keys_detected"))


def _risk_tier(score: int) -> str:
    for threshold, tier in TIERS:
        if score >= threshold:
            return tier
    return "low"


def score_asset(asset: dict[str, Any]) -> dict[str, Any]:
    """Return the asset with risk_score, risk_tier, and owasp_tags filled in."""
    tools = _tools(asset)
    status = str(asset.get("status", "")).upper()

    score = 0
    tags: list[str] = []

    if _is_exposed(asset) and not _requires_auth(asset):
        score += NO_AUTH_POINTS

    if _matches(tools, MUTATING_KEYWORDS):
        score += MUTATING_TOOL_POINTS

    if status == "ORPHANED":
        score += ORPHANED_POINTS
    elif status == "UNKNOWN":
        score += UNKNOWN_POINTS

    if _matches(tools, SHELL_KEYWORDS):
        score += SHELL_TOOL_POINTS
        tags.append("LLM01")

    if _holds_credentials(asset):
        score += CREDENTIAL_POINTS
        tags.append("LLM02")

    if _matches(tools, READ_KEYWORDS):
        score += READ_TOOL_POINTS
        tags.append("LLM02")

    # A poisoned description turns every other capability into an attack path:
    # the model obeys the injected instruction using the tools it already has.
    poison = asset.get("poison") or {}
    if poison.get("poisoned"):
        score += POISONED_TOOL_POINTS
        tags.extend(["LLM01", "MCP03"])

    # Drift is an integrity problem, not an injection: the served surface no
    # longer matches the approved one. It carries no hidden instruction, so it
    # earns neither the injection tag nor the poisoning weight.
    if poison.get("drifted"):
        score += CONFIG_DRIFT_POINTS
        tags.append("LLM04")

    if len(tools) > TOOL_SPRAWL_THRESHOLD:
        score += TOOL_SPRAWL_POINTS
        tags.append("LLM03")

    score = min(score, MAX_SCORE)

    scored = dict(asset)
    scored["risk_score"] = score
    scored["risk_tier"] = _risk_tier(score)
    scored["owasp_tags"] = sorted(set(tags))
    return scored


def score_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score every asset in a fleet."""
    return [score_asset(asset) for asset in assets]
