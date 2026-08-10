"""Threat narratives: what a risk score means, in a sentence a CISO can act on.

"Ghost MCP: 100/critical" says nothing about consequence. The same asset
described as an unsupervised server whose tool descriptions hide an instruction
to read SSH keys, and which can spawn children reaching eleven data sources,
is a decision someone can make.

Two backends. Composition from the scan's own facts is the default: it needs no
network, no key, and cannot invent a capability the scanner did not observe --
which also makes it safe to run live in front of judges. If ANTHROPIC_API_KEY is
set, the same facts are handed to Claude for a fluent rewrite, and any failure
falls back to the composed text rather than dropping the narrative.
"""

from __future__ import annotations

import os
from typing import Any

MODEL = "claude-opus-5"

SYSTEM = (
    "You write one-paragraph threat narratives for a security dashboard. "
    "Your audience is a CISO deciding what to fix first. Use only the facts "
    "given -- never invent capabilities, CVEs, or evidence. Three sentences at "
    "most: what the asset is and how exposed it is, what its tools can reach, "
    "and what an attacker gets from it. Plain declarative prose, no headings, "
    "no bullet points, no hedging."
)

# Matched as substrings of a tool name, so each keyword must be specific enough
# that the phrase is true of every tool it hits - which means carrying the verb
# wherever direction matters. Bare nouns overclaim in both axes: "exec" hits
# `execute_query` (a SQL call, not a shell), "delete" hits deleting documents
# from a vector collection, and "email" hits `read_email`, which sends nothing.
# A narrative that invents a capability is worse than no narrative.
CAPABILITY_PHRASES = (
    ("shell", "run shell commands"),
    ("list_secret", "read stored secrets"),
    ("get_secret", "read stored secrets"),
    ("read_secret", "read stored secrets"),
    ("list_credential", "read stored secrets"),
    ("get_credential", "read stored secrets"),
    ("spawn", "spawn child agents"),
    ("delete_file", "delete files"),
    ("send_email", "send mail"),
    ("send_mail", "send mail"),
    ("read_file", "read the filesystem"),
    ("list_director", "read the filesystem"),
    ("execute_query", "query databases"),
    ("query_db", "query databases"),
    ("sql", "query databases"),
    ("collection", "query the vector store"),
    ("upsert", "write to the vector store"),
    ("http", "reach external hosts"),
    ("fetch", "reach external hosts"),
)


def _capabilities(asset: dict[str, Any]) -> list[str]:
    tools = [str(tool).lower() for tool in asset.get("tools") or []]
    phrases: list[str] = []
    for keyword, phrase in CAPABILITY_PHRASES:
        if any(keyword in tool for tool in tools) and phrase not in phrases:
            phrases.append(phrase)
    return phrases


def _join(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


def _exposure(asset: dict[str, Any]) -> str:
    security = asset.get("security") or {}
    supervision = str(asset.get("supervision", ""))

    # An agent is a local process that calls out; it does not receive calls, so
    # "unauthenticated" describes nothing about it.
    if asset.get("type") == "agent":
        return "runs on this host and calls out to MCP servers"

    if not security.get("requires_auth", False):
        exposure = "accepts unauthenticated calls"
    else:
        exposure = f"authenticates via {security.get('auth_type') or 'an unnamed scheme'}"

    if supervision == "no_health_endpoint":
        return f"{exposure} and exposes no health endpoint, so nothing is monitoring it"
    if supervision == "unreachable":
        return f"{exposure} but no longer answers, so its configuration is stale"
    return exposure


def _poison_sentence(asset: dict[str, Any]) -> str:
    findings = (asset.get("poison") or {}).get("findings") or []
    if not findings:
        return ""

    kinds = {finding["kind"] for finding in findings}
    tools = sorted({f["tool"] for f in findings if f.get("tool") not in (None, "-")})
    target = f"The description it serves for {_join(tools)}" if tools else "Its tool definitions"

    if "invisible_characters" in kinds:
        return (
            f"{target} carries an instruction written in characters that do not "
            "render, so it passes human review while the model still reads it."
        )
    if "instruction_override" in kinds:
        return f"{target} carries an instruction aimed at the model rather than a description of the tool."
    if "config_drift" in kinds:
        return "It serves a tool that its approved configuration never declared."
    if "rug_pull" in kinds:
        return "Its tool definitions changed after they were approved."
    return f"{target} was flagged during inspection."


def _propagation_sentence(asset: dict[str, Any]) -> str:
    propagation = asset.get("propagation") or {}

    if asset.get("type") == "agent":
        sources = propagation.get("inherited_from") or []
        if not sources:
            return ""
        poisoned = " -- one of them serving a poisoned tool definition" if propagation.get(
            "poisoned_upstream"
        ) else ""
        return (
            f"It scores as high as the worst server it talks to ({_join(sources)}"
            f"{poisoned}), because it is the process that would execute an injected instruction."
        )

    if propagation.get("spawns_agents") and propagation.get("amplification", 0) > 0:
        direct = len(propagation.get("direct_data_sources") or [])
        effective = len(propagation.get("effective_data_sources") or [])
        return (
            f"Because it can spawn agents that inherit the calling agent's configuration, "
            f"its real blast radius is {effective} data sources rather than the {direct} "
            "its own tools touch."
        )
    return ""


def compose(asset: dict[str, Any]) -> str:
    """Build the narrative from the scan's own observations."""
    name = str(asset.get("name", "This asset"))
    kind = "agent" if asset.get("type") == "agent" else "MCP server"

    sentences = [f"{name} is an {kind} that {_exposure(asset)}."]

    capabilities = _capabilities(asset)
    if capabilities:
        sentences.append(f"Its tools can {_join(capabilities)}.")

    for sentence in (_poison_sentence(asset), _propagation_sentence(asset)):
        if sentence:
            sentences.append(sentence)

    return " ".join(sentences)


def _facts(asset: dict[str, Any]) -> str:
    propagation = asset.get("propagation") or {}
    findings = (asset.get("poison") or {}).get("findings") or []
    lines = [
        f"name: {asset.get('name')}",
        f"type: {asset.get('type')}",
        f"risk score: {asset.get('risk_score')} ({asset.get('risk_tier')})",
        f"status: {asset.get('status')} ({asset.get('supervision', 'unknown')})",
        f"requires auth: {(asset.get('security') or {}).get('requires_auth')}",
        f"tools: {', '.join(str(t) for t in asset.get('tools') or []) or 'none'}",
        f"OWASP flags: {', '.join(asset.get('owasp_tags') or []) or 'none'}",
    ]
    if findings:
        lines.append(
            "poisoning findings: "
            + "; ".join(f"{f['kind']} on {f['tool']} -- {f['detail']}" for f in findings)
        )
    if propagation:
        lines.append(f"propagation: {propagation}")
    return "\n".join(lines)


def _via_claude(asset: dict[str, Any], api_key: str) -> str | None:
    try:
        import anthropic
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=2000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=SYSTEM,
            output_config={"effort": "low"},
            messages=[{"role": "user", "content": _facts(asset)}],
        )
    except Exception:
        return None

    # Security content can trip the safety classifiers; a declined request
    # returns 200 with an empty or partial body, so check before reading it.
    if response.stop_reason == "refusal":
        return None

    text = " ".join(
        block.text for block in response.content if getattr(block, "type", None) == "text"
    ).strip()
    return text or None


def narrate(asset: dict[str, Any], api_key: str | None = None) -> tuple[str, str]:
    """Return (narrative, source) for one asset."""
    key = api_key if api_key is not None else os.environ.get("ANTHROPIC_API_KEY")
    if key:
        generated = _via_claude(asset, key)
        if generated:
            return generated, "claude"
    return compose(asset), "composed"


def annotate_narratives(
    assets: list[dict[str, Any]], api_key: str | None = None, min_tier: str = "high"
) -> list[dict[str, Any]]:
    """Attach a narrative to every asset at or above `min_tier`."""
    ranked = ["low", "medium", "high", "critical"]
    floor = ranked.index(min_tier) if min_tier in ranked else 0

    for asset in assets:
        tier = str(asset.get("risk_tier", "low"))
        if tier in ranked and ranked.index(tier) < floor:
            continue
        asset["threat_narrative"], asset["narrative_source"] = narrate(asset, api_key)
    return assets
