"""Tool poisoning detection.

An MCP server declares its tools to the agent as name + description. The agent
feeds those descriptions straight to the model, so a description is executable
text. Attackers use that: the human sees "Search the web", the model reads an
extra instruction appended to it.

Three families are detected here:

* hidden instructions in the served description (OWASP MCP03:2025, tracked as
  CVE-2025-54136 / MCPoison),
* payloads written in characters that do not render -- the Unicode Tags block
  and zero-width joiners -- so the description looks clean to a reviewer,
* definitions that change after approval (rug pull): every client caches the
  tool list at first load and none of them re-verifies it, so a server can
  serve a benign description on day one and a malicious one on day two.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

# Codepoints that carry text but render as nothing.
INVISIBLE_SINGLES = frozenset(
    "­"  # soft hyphen
    "​‌‍"  # zero-width space / non-joiner / joiner
    "⁠⁡⁢⁣⁤"  # word joiner, invisible operators
    "﻿"  # zero-width no-break space
    "‪‫‬‭‮"  # bidi embedding / override
    "⁦⁧⁨⁩"  # bidi isolates
)
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Every pattern here must target the *model's own instructions*. Imperative
# usage guidance ("You must authenticate first") is recommended practice in
# LLM-facing tool documentation, and "send a system message" is what a chat
# tool does for a living - neither is evidence of hijacking.
INSTRUCTION_OVERRIDE = (
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"system\s+(directive|prompt|override)\b",
    r"new\s+instructions?\s*:",
    r"before\s+(completing|answering|doing)\s+any\s+task",
    r"</?(system|instructions?)>",
)

CONCEALMENT = (
    r"do\s+not\s+(mention|tell|reveal|disclose|inform|show)",
    r"don'?t\s+(mention|tell|reveal|disclose|inform)",
    r"without\s+(telling|informing|notifying)",
    r"(mask|hide|conceal)\s+(this|it|the)",
    # "Silently retries on timeout" is ordinary API documentation; the bare
    # adverb is not a signal. Require something being withheld.
    r"silently\s+(hide|omit|drop|discard|suppress|forward|send|exfiltrat)",
)

# High-signal artefacts: naming these in a tool description is not normal.
SENSITIVE_ARTEFACTS = (
    r"~?/?\.ssh\b",
    r"\bid_rsa\b",
    r"\bid_ed25519\b",
    r"\.env\b",
    r"\bprivate\s+key\b",
)
SENSITIVE_TERMS = (
    r"\bapi[_\s-]?keys?\b",
    r"\baccess\s+tokens?\b",
    r"\bcredentials?\b",
    r"\bpasswords?\b",
    r"\bsecrets?\b",
)
# Naming a credential and naming a send verb are both normal - "Send an email
# using the configured SMTP credentials" is a real description. What is not
# normal is naming a destination to send it to.
EXFIL_DESTINATIONS = (
    r"https?://",
    r"\bftp://",
    r"\b\d{1,3}(\.\d{1,3}){3}\b",
    r"\b[\w-]+\.(com|net|org|io|co|ru|cn|xyz|top)\b/?",
)
EXFIL_VERBS = (
    r"\bsend\b",
    r"\bpost\b",
    r"\bupload\b",
    r"\btransmit\b",
    r"\bexfiltrat",
    r"\bforward\b",
    r"\bleak\b",
    r"\bcurl\b",
)

# A hidden instruction and a config mismatch are different claims. Only the
# first is tool poisoning; conflating them tags a server that hides nothing as
# a prompt-injection carrier.
POISONING_KINDS = frozenset({
    "instruction_override",
    "invisible_characters",
    "credential_exfiltration",
    "concealment",
    "rug_pull",
})

SEVERITY = {
    "instruction_override": "critical",
    "invisible_characters": "critical",
    "credential_exfiltration": "critical",
    "rug_pull": "critical",
    "concealment": "high",
    "config_drift": "high",
}

DEFAULT_BASELINE = os.path.expanduser("~/.agentguard/tool_baseline.json")


def strip_invisible(text: str) -> tuple[str, str]:
    """Split a description into what a human sees and what was hidden in it."""
    visible: list[str] = []
    hidden: list[str] = []
    for char in text:
        codepoint = ord(char)
        if TAG_BLOCK_START <= codepoint <= TAG_BLOCK_END:
            # Unicode Tags mirror ASCII: U+E0041 carries "A".
            decoded = codepoint - TAG_BLOCK_START
            hidden.append(chr(decoded) if 0x20 <= decoded <= 0x7E else "")
        elif char in INVISIBLE_SINGLES:
            hidden.append("")
        else:
            visible.append(char)
    return "".join(visible), "".join(hidden)


def _matches(patterns: tuple[str, ...], text: str) -> str | None:
    for pattern in patterns:
        found = re.search(pattern, text, re.IGNORECASE)
        if found:
            return found.group(0).strip()
    return None


def tool_fingerprints(tool_details: list[dict[str, Any]]) -> dict[str, str]:
    """SHA-256 per tool definition, so a later scan can prove nothing moved."""
    prints: dict[str, str] = {}
    for tool in tool_details or []:
        name = str(tool.get("name", ""))
        if not name:
            continue
        payload = json.dumps(
            {"name": name, "description": str(tool.get("description", ""))},
            sort_keys=True,
            ensure_ascii=False,
        )
        prints[name] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return prints


def _load_baseline(path: str) -> dict[str, Any]:
    try:
        with open(path) as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_baseline(path: str, data: dict[str, Any]) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
    except OSError:
        pass


def _scan_description(tool_name: str, description: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    visible, hidden = strip_invisible(description)

    # Zero-width characters carry no decodable text, so `hidden` stays empty for
    # them: presence is what the visible/original mismatch proves.
    if visible != description:
        findings.append(
            {
                "tool": tool_name,
                "kind": "invisible_characters",
                "detail": f"payload hidden in non-rendering characters: {hidden!r}"
                if hidden.strip()
                else "non-rendering characters embedded in the description",
            }
        )

    # Hidden text is the payload, so search it alongside what renders.
    haystack = f"{visible} {hidden}".strip()

    override = _matches(INSTRUCTION_OVERRIDE, haystack)
    if override:
        findings.append(
            {"tool": tool_name, "kind": "instruction_override",
             "detail": f"description gives the model an instruction: {override!r}"}
        )

    concealment = _matches(CONCEALMENT, haystack)
    if concealment:
        findings.append(
            {"tool": tool_name, "kind": "concealment",
             "detail": f"description asks the model to hide its behaviour: {concealment!r}"}
        )

    artefact = _matches(SENSITIVE_ARTEFACTS, haystack)
    term = _matches(SENSITIVE_TERMS, haystack)
    verb = _matches(EXFIL_VERBS, haystack)
    destination = _matches(EXFIL_DESTINATIONS, haystack)
    if artefact or (term and verb and destination):
        target = artefact or f"{verb} … {term} -> {destination}"
        findings.append(
            {"tool": tool_name, "kind": "credential_exfiltration",
             "detail": f"description references credential material: {target!r}"}
        )

    return findings


def detect_poisoning(
    asset: dict[str, Any], baseline_path: str | None = None
) -> dict[str, Any]:
    """Inspect one asset's served tool definitions.

    `baseline_path` enables rug-pull detection; without it only the current
    scan is judged, which keeps the check deterministic in tests.
    """
    details = asset.get("tool_details") or []
    findings: list[dict[str, str]] = []

    for tool in details:
        if not isinstance(tool, dict):
            continue
        findings.extend(
            _scan_description(str(tool.get("name", "?")), str(tool.get("description", "")))
        )

    # The config was reviewed and approved; the wire is what actually runs.
    declared = {str(name) for name in asset.get("declared_tools") or []}
    served = {str(tool.get("name")) for tool in details if isinstance(tool, dict)}
    if declared and served and served != declared:
        added = sorted(served - declared)
        removed = sorted(declared - served)
        parts = []
        if added:
            parts.append(f"serving undeclared {added}")
        if removed:
            parts.append(f"no longer serving {removed}")
        findings.append(
            {"tool": "-", "kind": "config_drift",
             "detail": "server disagrees with approved config: " + "; ".join(parts)}
        )

    prints = tool_fingerprints(details)

    if baseline_path and prints:
        baseline = _load_baseline(baseline_path)
        previous = baseline.get(str(asset.get("name", ""))) or {}
        for name, digest in prints.items():
            older = previous.get(name)
            if older and older != digest:
                findings.append(
                    {"tool": name, "kind": "rug_pull",
                     "detail": "tool definition changed since the last scan "
                               f"({older[:12]}… -> {digest[:12]}…)"}
                )
        baseline[str(asset.get("name", ""))] = prints
        _save_baseline(baseline_path, baseline)

    for finding in findings:
        finding["severity"] = SEVERITY.get(finding["kind"], "medium")

    kinds = {finding["kind"] for finding in findings}
    return {
        "poisoned": bool(kinds & POISONING_KINDS),
        "drifted": "config_drift" in kinds,
        "findings": findings,
        "tool_hashes": prints,
    }


def annotate_assets(
    assets: list[dict[str, Any]], baseline_path: str | None = DEFAULT_BASELINE
) -> list[dict[str, Any]]:
    """Attach a `poison` block to every asset that serves tool definitions."""
    for asset in assets:
        asset["poison"] = detect_poisoning(asset, baseline_path=baseline_path)
    return assets
