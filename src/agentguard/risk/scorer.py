"""Risk scoring with OWASP LLM Top 10 tagging."""

from __future__ import annotations

from typing import Any

NO_AUTH_POINTS = 40
MUTATING_TOOL_POINTS = 25
ORPHANED_POINTS = 20
UNKNOWN_POINTS = 10
SHELL_TOOL_POINTS = 8
READ_TOOL_POINTS = 4
TOOL_SPRAWL_POINTS = 3

TOOL_SPRAWL_THRESHOLD = 5
MAX_SCORE = 100

TIERS = [(75, "critical"), (50, "high"), (25, "medium")]

MUTATING_KEYWORDS = ("write", "delete", "exec", "create", "update", "drop", "remove", "put", "post")
SHELL_KEYWORDS = ("shell", "cmd", "command", "bash", "terminal", "subprocess", "run")
READ_KEYWORDS = ("file", "read", "db", "database", "query", "sql", "fetch", "get", "list", "search")

OWASP_LABELS = {
    "LLM01": "LLM01: Prompt Injection",
    "LLM06": "LLM06: Sensitive Information Disclosure",
    "LLM08": "LLM08: Excessive Agency",
}


def _tools(asset: dict[str, Any]) -> list[str]:
    tools = asset.get("tools") or []
    return [str(tool).lower() for tool in tools]


def _matches(tools: list[str], keywords: tuple[str, ...]) -> bool:
    return any(keyword in tool for tool in tools for keyword in keywords)


def _requires_auth(asset: dict[str, Any]) -> bool:
    security = asset.get("security") or {}
    if "requires_auth" in security:
        return bool(security["requires_auth"])
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

    if not _requires_auth(asset):
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

    if _matches(tools, READ_KEYWORDS):
        score += READ_TOOL_POINTS
        tags.append("LLM06")

    if len(tools) > TOOL_SPRAWL_THRESHOLD:
        score += TOOL_SPRAWL_POINTS
        tags.append("LLM08")

    score = min(score, MAX_SCORE)

    scored = dict(asset)
    scored["risk_score"] = score
    scored["risk_tier"] = _risk_tier(score)
    scored["owasp_tags"] = tags
    return scored


def score_assets(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Score every asset in a fleet."""
    return [score_asset(asset) for asset in assets]
