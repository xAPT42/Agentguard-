"""Discovery of MCP servers from local agent configs and listening ports."""

from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path
from typing import Any

import requests

SCAN_PORTS = [3000, 5000, 8080, 8888, 9000]
SOCKET_TIMEOUT = 1.0
HTTP_TIMEOUT = 1.0
HEALTH_PATHS = ["/health", "/mcp"]
MCP_PATH = "/mcp"

MCP_PROBE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "agentguard", "version": "0.1.0"},
    },
}
MCP_PROBE_HEADERS = {"Accept": "application/json, text/event-stream"}
MCP_BODY_MARKERS = ("jsonrpc", "protocolversion", "serverinfo", "result")
MCP_AUTH_STATUSES = (401, 403)
MCP_ENDPOINT_STATUSES = (400, 405, 406, 415)

CONFIG_PATHS = [
    Path.home() / ".claude" / "settings.json",
    Path.cwd() / ".mcp.json",
    Path.cwd() / ".cursorrules",
]

AUTH_ENV_HINTS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")


def _detect_auth(entry: dict[str, Any]) -> dict[str, Any]:
    headers = entry.get("headers") or {}
    for header in headers:
        lowered = header.lower()
        if lowered == "authorization":
            value = str(headers[header])
            auth_type = value.split(" ", 1)[0] if " " in value else "bearer"
            return {"requires_auth": True, "auth_type": auth_type.lower()}
        if lowered.startswith("x-api-key") or lowered.endswith("api-key"):
            return {"requires_auth": True, "auth_type": "api_key"}

    env = entry.get("env") or {}
    for name in env:
        if any(hint in name.upper() for hint in AUTH_ENV_HINTS):
            return {"requires_auth": True, "auth_type": "env_credential"}

    if entry.get("auth") or entry.get("authentication"):
        return {"requires_auth": True, "auth_type": "configured"}

    return {"requires_auth": False, "auth_type": None}


def _entry_url(entry: dict[str, Any]) -> str | None:
    for key in ("url", "endpoint", "serverUrl", "httpUrl"):
        value = entry.get(key)
        if isinstance(value, str) and value.startswith("http"):
            return value
    return None


def _entry_tools(entry: dict[str, Any]) -> list[str]:
    tools = entry.get("tools") or entry.get("allowedTools") or []
    if isinstance(tools, dict):
        return sorted(str(name) for name in tools)
    if isinstance(tools, list):
        return [str(tool) for tool in tools]
    return []


def _probe_http(url: str) -> bool:
    for path in HEALTH_PATHS:
        target = url.rstrip("/") + path
        try:
            response = requests.get(target, timeout=HTTP_TIMEOUT)
        except requests.RequestException:
            continue
        if response.status_code < 500:
            return True
    return False


def _probe_mcp(url: str) -> dict[str, Any] | None:
    """Return security info if the endpoint speaks MCP, else None.

    A generic /health route proves only that something is listening. Discovery
    requires the JSON-RPC endpoint itself to answer, so ordinary web services
    are not catalogued as MCP servers.
    """
    target = url.rstrip("/") + MCP_PATH
    try:
        response = requests.post(
            target,
            json=MCP_PROBE,
            headers=MCP_PROBE_HEADERS,
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException:
        return None

    if response.status_code in MCP_AUTH_STATUSES:
        return {"requires_auth": True, "auth_type": "unknown"}

    if response.status_code in (200, 202):
        body = response.text[:1000].lower()
        if any(marker in body for marker in MCP_BODY_MARKERS):
            return {"requires_auth": False, "auth_type": None}
        return None

    if response.status_code in MCP_ENDPOINT_STATUSES:
        return {"requires_auth": False, "auth_type": None}

    return None


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT):
            return True
    except OSError:
        return False


def _url_alive(url: str) -> bool:
    match = re.match(r"https?://([^:/]+)(?::(\d+))?", url)
    if not match:
        return False
    host = match.group(1)
    port = int(match.group(2)) if match.group(2) else (443 if url.startswith("https") else 80)
    if not _port_open(host, port):
        return False
    return _probe_http(url)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _mcp_entries(data: dict[str, Any]) -> dict[str, Any]:
    for key in ("mcpServers", "mcp_servers", "servers"):
        entries = data.get(key)
        if isinstance(entries, dict):
            return entries
    return {}


def _parse_cursorrules(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return _mcp_entries(data)
    except json.JSONDecodeError:
        pass

    entries: dict[str, Any] = {}
    for url in re.findall(r"https?://[^\s\"'`,)]+", text):
        if "mcp" not in url.lower():
            continue
        name = re.sub(r"[^a-z0-9]+", "-", url.lower()).strip("-")
        entries[name] = {"url": url}
    return entries


def _from_configs() -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    seen: set[str] = set()

    for path in CONFIG_PATHS:
        if not path.is_file():
            continue
        entries = _parse_cursorrules(path) if path.suffix != ".json" else _mcp_entries(_load_json(path))
        for name, entry in entries.items():
            if not isinstance(entry, dict) or name in seen:
                continue
            seen.add(name)
            url = _entry_url(entry)
            alive = _url_alive(url) if url else _command_alive(entry)
            assets.append(
                {
                    "type": "mcp_server",
                    "name": name,
                    "url": url or entry.get("command") or "",
                    "tools": _entry_tools(entry),
                    "status": "ACTIVE" if alive else "ORPHANED",
                    "discovered_via": "config",
                    "security": _detect_auth(entry),
                    "risk_score": 0,
                    "config_path": str(path),
                }
            )
    return assets


def _command_alive(entry: dict[str, Any]) -> bool:
    command = entry.get("command")
    if not command:
        return False
    binary = os.path.basename(str(command))
    try:
        import subprocess

        result = subprocess.run(
            ["pgrep", "-f", binary],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


def _from_ports(known_urls: set[str]) -> list[dict[str, Any]]:
    assets = []
    for port in SCAN_PORTS:
        if not _port_open("127.0.0.1", port):
            continue
        url = f"http://127.0.0.1:{port}"
        if url in known_urls:
            continue
        security = _probe_mcp(url)
        if security is None:
            continue
        assets.append(
            {
                "type": "mcp_server",
                "name": f"mcp-port-{port}",
                "url": url,
                "tools": [],
                "status": "ACTIVE",
                "discovered_via": "port_scan",
                "security": security,
                "risk_score": 0,
            }
        )
    return assets


def scan_mcp_servers() -> list[dict[str, Any]]:
    """Return every MCP server found in local configs or listening on known ports."""
    assets = _from_configs()
    known_urls = {asset["url"].rstrip("/") for asset in assets if asset.get("url")}
    assets.extend(_from_ports(known_urls))
    return assets
