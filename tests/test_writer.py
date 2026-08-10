"""Tests for what lands on a DataHub entity.

These cover the tag and property surface a reviewer actually reads in the
catalog. Two of them lock in bugs this file already shipped once: drift being
tagged as poisoning, and the same tag appearing twice.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.datahub.writer import (  # noqa: E402
    _custom_properties,
    _poison_properties,
    _propagation_properties,
    _tags,
    build_urn,
)


def _asset(**extra):
    asset = {"type": "mcp_server", "name": "Ghost MCP", "tools": ["exec_shell"],
             "risk_tier": "critical", "risk_score": 100, "status": "ACTIVE",
             "security": {"requires_auth": False}}
    asset.update(extra)
    return asset


# --- URNs ---------------------------------------------------------------------

def test_urn_is_normalised_and_stable():
    urn = build_urn(_asset(name="Ghost MCP"))
    assert urn == "urn:li:mlModel:(urn:li:dataPlatform:mcp,ghost-mcp,PROD)"


# --- tags ---------------------------------------------------------------------

def test_a_clean_asset_carries_no_poisoning_tag():
    tags = _tags(_asset(poison={"poisoned": False, "drifted": False, "findings": []}))
    assert "context-poisoned" not in tags
    assert "config-drift" not in tags


def test_drift_is_tagged_as_drift_not_as_poisoning():
    tags = _tags(_asset(poison={
        "poisoned": False, "drifted": True,
        "findings": [{"kind": "config_drift", "tool": "-", "detail": "x"}]}))
    assert "config-drift" in tags
    assert "context-poisoned" not in tags, tags


def test_poisoning_is_tagged_with_its_finding_kinds():
    tags = _tags(_asset(poison={
        "poisoned": True, "drifted": False,
        "findings": [
            {"kind": "invisible_characters", "tool": "t", "detail": "x"},
            {"kind": "instruction_override", "tool": "t", "detail": "x"}]}))
    assert "context-poisoned" in tags
    assert "invisible-characters" in tags and "instruction-override" in tags


def test_tags_are_not_repeated():
    tags = _tags(_asset(poison={
        "poisoned": False, "drifted": True,
        "findings": [{"kind": "config_drift", "tool": "-", "detail": "x"}]}))
    assert len(tags) == len(set(tags)), tags


def test_an_unsupervised_asset_is_tagged_orphaned():
    assert "orphaned" in _tags(_asset(status="ORPHANED"))


# --- properties ---------------------------------------------------------------

def test_poison_properties_separate_poisoning_from_drift():
    props = _poison_properties(_asset(poison={
        "poisoned": False, "drifted": True,
        "findings": [{"kind": "config_drift", "tool": "-", "detail": "d"}]}))
    assert props["agentguard.poison.detected"] == "false"
    assert props["agentguard.drift.detected"] == "true"


def test_poison_properties_name_the_affected_tool_and_payload():
    props = _poison_properties(_asset(poison={
        "poisoned": True, "drifted": False,
        "findings": [{"kind": "invisible_characters", "tool": "query_collection",
                      "detail": "payload hidden in non-rendering characters: 'IGNORE'"}]}))
    assert props["agentguard.poison.tools"] == "query_collection"
    assert "IGNORE" in props["agentguard.poison.detail"]


def test_a_clean_asset_reports_no_poisoning_rather_than_nothing():
    props = _poison_properties(_asset())
    assert props == {"agentguard.poison.detected": "false"}


def test_propagation_properties_differ_by_asset_type():
    agent = _propagation_properties({
        "type": "agent", "propagation": {
            "inherited_score": 100, "inherited_from": ["Ghost MCP"],
            "poisoned_upstream": True}})
    assert agent["agentguard.propagation.inherited_score"] == "100"
    assert agent["agentguard.propagation.poisoned_upstream"] == "true"

    server = _propagation_properties(_asset(propagation={
        "spawns_agents": True, "amplification": 6,
        "direct_data_sources": ["OS Shell"], "effective_data_sources": ["OS Shell", "Email"]}))
    assert server["agentguard.propagation.amplification"] == "6"
    assert "inherited_score" not in " ".join(server)


def test_custom_properties_carry_the_score_and_supervision_state():
    props = _custom_properties(_asset(supervision="no_health_endpoint"))
    assert props["agentguard.risk_score"] == "100"
    assert props["agentguard.supervision"] == "no_health_endpoint"


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
