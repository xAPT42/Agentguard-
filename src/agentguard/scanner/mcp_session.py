"""Minimal MCP client over streamable HTTP.

Spec-compliant servers - DataHub's among them - hand out a session on
`initialize`, expect a `notifications/initialized` acknowledgement, and reject
anything else until both have happened. A bare `tools/list` POST gets nothing
back, which is how a real server can look toolless to a naive scanner.

Responses arrive as SSE frames or plain JSON depending on the server, so both
are parsed here.
"""

from __future__ import annotations

import json
from typing import Any

import requests

PROTOCOL_VERSION = "2024-11-05"
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


def _body(response: requests.Response) -> dict[str, Any] | None:
    """Read a JSON-RPC result from a plain JSON body or an SSE frame."""
    text = response.text or ""
    if text.lstrip().startswith("{"):
        try:
            return json.loads(text)
        except ValueError:
            return None
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except ValueError:
                continue
    return None


class McpSession:
    """One initialized MCP conversation with a server."""

    def __init__(self, url: str, timeout: float = 8.0, token: str | None = None):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.headers = dict(HEADERS)
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self._id = 0

    def _post(self, payload: dict[str, Any]) -> requests.Response:
        return requests.post(
            self.url, json=payload, headers=self.headers, timeout=self.timeout
        )

    def _call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        self._id += 1
        response = self._post(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        )
        if response.status_code not in (200, 202):
            return None
        return _body(response)

    def open(self) -> bool:
        """Run the handshake. Returns False if the server never completes it."""
        try:
            response = self._post({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "agentguard", "version": "0.1.0"},
                },
            })
        except requests.RequestException:
            return False

        if response.status_code not in (200, 202):
            return False

        session = response.headers.get("Mcp-Session-Id") or response.headers.get("mcp-session-id")
        if session:
            self.headers["Mcp-Session-Id"] = session

        body = _body(response)
        if not body or "result" not in body:
            return False

        # A server that hands out a session will refuse everything else until
        # it is acknowledged.
        try:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        except requests.RequestException:
            return False
        return True

    def tools(self) -> list[dict[str, str]]:
        """Tool definitions as this server serves them, names and descriptions."""
        try:
            body = self._call("tools/list")
        except requests.RequestException:
            return []
        if not body:
            return []

        served = []
        for tool in (body.get("result") or {}).get("tools") or []:
            if isinstance(tool, dict) and tool.get("name"):
                served.append({
                    "name": str(tool["name"]),
                    "description": str(tool.get("description") or ""),
                })
        return served

    def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool and return its unwrapped content."""
        try:
            body = self._call("tools/call", {"name": name, "arguments": arguments})
        except requests.RequestException:
            return None
        if not body or "result" not in body:
            return None

        content = (body["result"] or {}).get("content") or []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                raw = block.get("text", "")
                try:
                    return json.loads(raw)
                except ValueError:
                    return raw
        return body["result"]
