"""Tests for the MCP wire parsing.

A spec-compliant server answers over SSE; a hand-rolled one answers with plain
JSON. Reading only one of the two is how a real server looks toolless.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentguard.scanner.mcp_session import _body  # noqa: E402


class _Fake:
    def __init__(self, text):
        self.text = text


def test_plain_json_body_is_parsed():
    body = _body(_Fake('{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'))
    assert body is not None and "result" in body


def test_sse_frame_is_parsed():
    body = _body(_Fake(
        'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search"}]}}\n\n'
    ))
    assert body is not None
    assert body["result"]["tools"][0]["name"] == "search"


def test_sse_with_leading_whitespace_and_multiple_lines():
    body = _body(_Fake(
        'id: 7\nevent: message\ndata: {"jsonrpc":"2.0","result":{"ok":true}}\n'
    ))
    assert body is not None and body["result"]["ok"] is True


def test_a_body_that_is_not_json_returns_none():
    assert _body(_Fake("<html>gateway timeout</html>")) is None


def test_an_empty_body_returns_none():
    assert _body(_Fake("")) is None


def test_malformed_sse_payload_returns_none_rather_than_raising():
    assert _body(_Fake("data: {not json at all\n")) is None


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
