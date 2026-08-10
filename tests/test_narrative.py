"""Tests for threat narratives.

The composed backend must never state a capability the scanner did not observe:
a narrative that invents one is worse than no narrative, and it is the failure
this module was already caught doing once.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.risk.narrative import compose, narrate  # noqa: E402


def _server(name, tools, **extra):
    asset = {"type": "mcp_server", "name": name, "tools": tools,
             "security": {"requires_auth": False}, "status": "ACTIVE"}
    asset.update(extra)
    return asset


# --- capabilities must trace back to a real tool ------------------------------

def test_a_sql_tool_is_not_narrated_as_a_shell():
    text = compose(_server("DataHub MCP", ["get_dataset", "execute_query"]))
    assert "query databases" in text
    assert "shell" not in text, text


def test_deleting_documents_is_not_narrated_as_deleting_files():
    text = compose(_server("Chroma VectorDB", ["query_collection", "insert", "delete"]))
    assert "delete files" not in text, text


def test_reading_mail_is_not_narrated_as_sending_it():
    text = compose(_server("Inbox MCP", ["read_email", "list_emails"]))
    assert "send mail" not in text, text


def test_sending_mail_is_narrated():
    assert "send mail" in compose(_server("Mailer", ["send_email"]))


def test_rotating_a_secret_is_not_narrated_as_reading_one():
    text = compose(_server("Vault MCP", ["rotate_credential", "create_secret"]))
    assert "read stored secrets" not in text, text


def test_listing_secrets_is_narrated_as_reading_them():
    assert "read stored secrets" in compose(_server("Ghost MCP", ["list_secrets"]))


# --- an agent is not a listening server ---------------------------------------

def test_an_agent_is_not_described_as_accepting_calls():
    agent = {"type": "agent", "name": "claude", "command": "claude", "tools": []}
    text = compose(agent)
    assert "unauthenticated calls" not in text, text
    assert "calls out to MCP servers" in text


# --- supervision and findings -------------------------------------------------

def test_an_unsupervised_server_says_nothing_is_monitoring_it():
    text = compose(_server("Ghost MCP", ["exec_shell"],
                           status="ORPHANED", supervision="no_health_endpoint"))
    assert "no health endpoint" in text and "monitoring" in text


def test_an_invisible_payload_is_described_as_non_rendering():
    asset = _server("Chroma VectorDB", ["query_collection"])
    asset["poison"] = {"poisoned": True, "findings": [
        {"kind": "invisible_characters", "tool": "query_collection", "detail": "x"}]}
    assert "do not render" in compose(asset)


def test_drift_is_not_described_as_a_hidden_instruction():
    asset = _server("DataHub MCP", ["execute_query"])
    asset["poison"] = {"poisoned": False, "drifted": True, "findings": [
        {"kind": "config_drift", "tool": "-", "detail": "x"}]}
    text = compose(asset)
    assert "never declared" in text
    assert "instruction" not in text, text


def test_amplification_is_stated_for_a_spawning_server():
    asset = _server("Ghost MCP", ["spawn_agent"])
    asset["propagation"] = {"spawns_agents": True, "amplification": 6,
                            "direct_data_sources": ["a"] * 5,
                            "effective_data_sources": ["a"] * 11}
    text = compose(asset)
    assert "11 data sources rather than the 5" in text


def test_an_agent_states_where_its_score_came_from():
    agent = {"type": "agent", "name": "claude", "command": "claude", "tools": [],
             "propagation": {"inherited_from": ["Ghost MCP"], "poisoned_upstream": True}}
    text = compose(agent)
    assert "Ghost MCP" in text and "poisoned" in text


# --- backend selection --------------------------------------------------------

def test_without_a_key_the_composed_backend_is_used():
    text, source = narrate(_server("Qdrant Search", ["search"]), api_key="")
    assert source == "composed"
    assert text


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
