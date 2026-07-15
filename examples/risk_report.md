# AgentGuard Risk Report

**Scan date:** 2026-07-15 · **Scope:** 1 host, 3 config files, 5 ports · **Assets found:** 4

## Fleet summary

| Asset | Type | Status | Risk | Tier | OWASP |
|---|---|---|---|---|---|
| Ghost MCP | mcp_server | ORPHANED | 85 | critical | LLM01, LLM06, LLM08 |
| LangChain Agent | agent | ACTIVE | 67 | high | LLM01, LLM08 |
| Claude MCP | mcp_server | ACTIVE | 42 | medium | LLM06 |
| DataHub MCP | mcp_server | ACTIVE | 15 | low | — |

**1 critical asset.** This scan exits with code 1, failing the pipeline.

## Critical: Ghost MCP (85)

An MCP server declared in `~/.claude/settings.json` that no longer responds on `10.4.12.87:9000`. It is unauthenticated and its declared toolset includes `exec_shell`, `delete_file`, and `list_secrets`.

Orphaned servers are the highest-value finding in a fleet scan. The config entry means an agent will still try to reach this endpoint, and nothing is currently listening on that address — anything that binds that host and port inherits a trusted, unauthenticated shell tool.

- **LLM01 (Prompt Injection):** `exec_shell` reachable with no auth boundary.
- **LLM06 (Sensitive Information Disclosure):** `list_secrets` and `query_db` exposed.
- **LLM08 (Excessive Agency):** 6 tools including irreversible `delete_file`.

**Remediation**
1. Remove the entry from `~/.claude/settings.json` if the server is retired.
2. If still required, redeploy with bearer auth and drop `exec_shell` and `list_secrets` from the toolset.
3. Confirm no other host can claim `10.4.12.87:9000`.

## High: LangChain Agent (67)

Process `48211` running `langchain_app.server` with `OPENAI_API_KEY`, `LANGCHAIN_API_KEY`, and `LANGCHAIN_TRACING_V2` in its environment. It holds `run_shell` and `send_email` in the same toolset.

Shell execution combined with an outbound channel is the classic injection-to-exfiltration path: untrusted content reaching the model can drive a command whose output leaves over email.

- **LLM01 (Prompt Injection):** `run_shell` plus `http_fetch` on untrusted input.
- **LLM08 (Excessive Agency):** 6 tools spanning read, write, execute, and send.

**Remediation**
1. Split `run_shell` into a separate, allowlisted agent; remove it from the email-capable one.
2. Move credentials from the process environment to a secret manager with short-lived tokens.
3. Add an AI-generated content disclosure to outbound email (EU AI Act Art. 50).

## Medium: Claude MCP (42)

Found by port scan on `127.0.0.1:3000` — not declared in any config file, which means it was never reviewed. Unauthenticated read access to the source tree.

- **LLM06 (Sensitive Information Disclosure):** `read_file` and `search_codebase` with no auth.

**Remediation**
1. Enable authentication even on loopback; container networking routinely makes loopback reachable.
2. Declare the server in `.mcp.json` so it enters the review path.

## Low: DataHub MCP (15)

Bearer auth enforced, owner assigned, read-only metadata tools. This is the intended baseline.

## Prioritized actions

| # | Action | Asset | Reduces |
|---|---|---|---|
| 1 | Remove or re-authenticate the orphaned endpoint | Ghost MCP | 85 → 0 |
| 2 | Separate shell execution from the email tool | LangChain Agent | 67 → 34 |
| 3 | Move API keys out of process env | LangChain Agent | — |
| 4 | Enable auth on port 3000 | Claude MCP | 42 → 4 |

**Fleet risk after remediation:** 1 critical → 0.
