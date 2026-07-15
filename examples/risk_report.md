# AgentGuard Risk Report

**Scan date:** 2026-07-15 · **Scope:** 1 host, 3 config files, 5 ports · **Assets found:** 4

## Fleet summary

| Asset | Type | Status | Risk | Tier | OWASP |
|---|---|---|---|---|---|
| Ghost MCP | mcp_server | ORPHANED | 100 | critical | LLM01, LLM06, LLM08 |
| Claude MCP | mcp_server | ACTIVE | 44 | medium | LLM06 |
| LangChain Agent | agent | ACTIVE | 40 | medium | LLM01, LLM06, LLM08 |
| DataHub MCP | mcp_server | ACTIVE | 4 | low | LLM06 |

**1 critical asset.** This scan exits with code 1, failing the pipeline.

## Critical: Ghost MCP (100)

An MCP server declared in `~/.claude/settings.json` that no longer responds on `10.4.12.87:9000`. It is unauthenticated and its declared toolset includes `exec_shell`, `delete_file`, and `list_secrets`.

Orphaned servers are the highest-value finding in a fleet scan. The config entry means an agent will still try to reach this endpoint, and nothing is currently listening on that address — anything that binds that host and port inherits a trusted, unauthenticated shell tool.

- **LLM01 (Prompt Injection):** `exec_shell` reachable with no auth boundary.
- **LLM06 (Sensitive Information Disclosure):** `list_secrets` and `query_db` exposed.
- **LLM08 (Excessive Agency):** 6 tools including irreversible `delete_file`.

**Remediation**
1. Remove the entry from `~/.claude/settings.json` if the server is retired.
2. If still required, redeploy with bearer auth and drop `exec_shell` and `list_secrets` from the toolset.
3. Confirm no other host can claim `10.4.12.87:9000`.

## Medium: Claude MCP (44)

Found by port scan on `127.0.0.1:3000` — not declared in any config file, which means it was never reviewed. Unauthenticated read access to the source tree.

- **LLM06 (Sensitive Information Disclosure):** `read_file` and `search_codebase` with no auth.

**Remediation**
1. Enable authentication even on loopback; container networking routinely makes loopback reachable.
2. Declare the server in `.mcp.json` so it enters the review path.

## Medium: LangChain Agent (40)

Process `48211` running `langchain_app.server` with `OPENAI_API_KEY`, `LANGCHAIN_API_KEY`, and `LANGCHAIN_TRACING_V2` in its environment. It holds `run_shell` and `send_email` in the same toolset.

Shell execution combined with an outbound channel is the classic injection-to-exfiltration path: untrusted content reaching the model can drive a command whose output leaves over email.

- **LLM01 (Prompt Injection):** `run_shell` plus `http_fetch` on untrusted input.
- **LLM06 (Sensitive Information Disclosure):** `read_file` and `search_index` over the local tree.
- **LLM08 (Excessive Agency):** 6 tools spanning read, write, execute, and send.

**Read the score with care.** At 40 this agent ranks below the read-only Claude MCP, despite holding the more dangerous capability. The scorer applies its +40 no-authentication penalty only to assets that expose an unauthenticated surface; this agent presents credentials, so that penalty never lands and its shell access is worth just +8. Tool-level agency is under-weighted relative to authentication. Treat the OWASP tags, not the score, as the signal here.

**Remediation**
1. Split `run_shell` into a separate, allowlisted agent; remove it from the email-capable one.
2. Move credentials from the process environment to a secret manager with short-lived tokens.
3. Add an AI-generated content disclosure to outbound email (EU AI Act Art. 50).

## Low: DataHub MCP (4)

Bearer auth enforced, owner assigned, read-only metadata tools. This is the intended baseline. It scores 4 rather than 0 because `get_dataset` is a read tool (**LLM06**) — a floor that read access always carries.

## Prioritized actions

| # | Action | Asset | Reduces |
|---|---|---|---|
| 1 | Remove or re-authenticate the orphaned endpoint | Ghost MCP | 100 → 0 |
| 2 | Separate shell execution from the email tool | LangChain Agent | 40 → 29 |
| 3 | Move API keys out of process env | LangChain Agent | — |
| 4 | Enable auth on port 3000 | Claude MCP | 44 → 4 |

**Fleet risk after remediation:** 1 critical → 0.
