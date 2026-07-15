"""Discovery of AI agents from running processes, containers, and env files."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

PROCESS_PATTERNS = {
    "claude": r"\bclaude\b",
    "langchain": r"\blangchain\b",
    "autogen": r"\bautogen\b",
    "crewai": r"\bcrewai\b",
    "ollama": r"\bollama\b",
    "openai-agent": r"\bopenai[-_]agent\b",
}

DOCKER_IMAGE_HINTS = (
    "claude",
    "langchain",
    "autogen",
    "crewai",
    "ollama",
    "openai",
    "anthropic",
    "llm",
    "agent",
    "vllm",
    "litellm",
)

KEY_PATTERNS = (
    re.compile(r"^ANTHROPIC_API_KEY$"),
    re.compile(r"^OPENAI_API_KEY$"),
    re.compile(r"^LANGCHAIN_.*$"),
    re.compile(r"^AGENT_.*$"),
)

ENV_SCAN_ROOTS = [Path.cwd(), Path.home() / "projects"]
ENV_SCAN_DEPTH = 2
SUBPROCESS_TIMEOUT = 5


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def _scan_processes() -> list[dict[str, Any]]:
    output = _run(["ps", "aux"])
    if not output:
        return []

    assets = []
    for line in output.splitlines()[1:]:
        fields = line.split(None, 10)
        if len(fields) < 11:
            continue
        pid, command = fields[1], fields[10]
        lowered = command.lower()
        if "agentguard" in lowered:
            continue
        for name, pattern in PROCESS_PATTERNS.items():
            if not re.search(pattern, lowered):
                continue
            assets.append(
                {
                    "type": "agent",
                    "name": name,
                    "source": "process",
                    "pid": int(pid) if pid.isdigit() else None,
                    "container_id": None,
                    "api_keys_detected": [],
                    "status": "ACTIVE",
                    "risk_score": 0,
                    "command": command[:200],
                }
            )
            break
    return assets


def _scan_docker() -> list[dict[str, Any]]:
    if not shutil.which("docker"):
        return []
    output = _run(["docker", "ps", "--format", "json"])
    if not output:
        return []

    assets = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            container = json.loads(line)
        except json.JSONDecodeError:
            continue
        image = str(container.get("Image", "")).lower()
        names = str(container.get("Names", "")).lower()
        if not any(hint in image or hint in names for hint in DOCKER_IMAGE_HINTS):
            continue
        assets.append(
            {
                "type": "agent",
                "name": container.get("Names") or image,
                "source": "docker",
                "pid": None,
                "container_id": container.get("ID"),
                "api_keys_detected": [],
                "status": "ACTIVE",
                "risk_score": 0,
                "image": container.get("Image"),
            }
        )
    return assets


def _key_names(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    names = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().removeprefix("export ").strip()
        if any(pattern.match(key) for pattern in KEY_PATTERNS):
            names.append(key)
    return sorted(set(names))


def _env_files() -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    for root in ENV_SCAN_ROOTS:
        if not root.is_dir():
            continue
        candidates = [root / ".env"]
        for depth in range(1, ENV_SCAN_DEPTH + 1):
            candidates.extend(root.glob("/".join(["*"] * depth) + "/.env"))
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if candidate.is_file() and resolved not in seen:
                seen.add(resolved)
                files.append(candidate)
    return files


def _scan_env_files() -> list[dict[str, Any]]:
    assets = []
    for path in _env_files():
        keys = _key_names(path)
        if not keys:
            continue
        assets.append(
            {
                "type": "agent",
                "name": path.parent.name or "root",
                "source": "env_file",
                "pid": None,
                "container_id": None,
                "api_keys_detected": keys,
                "status": "UNKNOWN",
                "risk_score": 0,
                "env_path": str(path),
            }
        )
    return assets


def scan_agents() -> list[dict[str, Any]]:
    """Return every AI agent found in processes, containers, or project env files."""
    return _scan_processes() + _scan_docker() + _scan_env_files()
