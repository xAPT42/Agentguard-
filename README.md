# AgentGuard

**Your organization deploys AI agents. Do you know where they all are?**

AgentGuard discovers every AI agent and MCP server running across your environment, scores each one for risk, and publishes the inventory to DataHub as governed metadata — so your agent fleet lives in the same catalog as the rest of your data estate.

```
$ agentguard
Scanning for MCP servers and AI agents...
NAME            | TYPE       | STATUS   | RISK | TIER
----------------+------------+----------+------+---------
Ghost MCP       | mcp_server | ORPHANED | 100  | critical
Claude MCP      | mcp_server | ACTIVE   | 44   | medium
LangChain Agent | agent      | ACTIVE   | 40   | medium
DataHub MCP     | mcp_server | ACTIVE   | 4    | low

4 asset(s) discovered — critical: 1, low: 1, medium: 2
Report written to scan_output.json
DataHub: 4 written, 0 failed

FAIL: 1 critical asset(s) require attention.
```

## Why AgentGuard

Agents arrive the way shadow IT always has: one developer, one useful integration, no ticket. The result is a fleet nobody has a complete list of.

- **75% of CIOs** report no clear visibility into the AI agents running in their organization.
- **82% of organizations** that ran a first inventory discovered agents they did not know existed.
- **Gartner projects 150,000 agents** per large enterprise by 2028.
- **The EU AI Act becomes applicable on 2 August 2026.** Its obligations — accountable owner, documented data access scope, disclosure, risk classification — all presuppose an inventory. You cannot document a fleet you cannot enumerate.

The specific failure mode AgentGuard exists to catch is the **orphaned MCP server**: an entry still sitting in an agent's config, pointing at an endpoint that no longer answers. The agent keeps trying to reach it. Whatever binds that host and port next inherits a trusted, often unauthenticated connection from a live agent.

## How it works

```
   ┌──────────────────────────────────────────────┐
   │                   SCANNER                    │
   │  configs · ports · processes · docker · env  │
   └──────────────────────┬───────────────────────┘
                          │  assets
                          ▼
   ┌──────────────────────────────────────────────┐
   │                    SCORER                    │
   │   risk 0-100 · tier · OWASP LLM Top 10 tags  │
   └──────────────────────┬───────────────────────┘
                          │  scored assets
                          ▼
   ┌──────────────────────────────────────────────┐
   │                   DATAHUB                    │
   │  mlModel · tags · ownership · EU AI Act ·    │
   │  lineage: agent → mcp_server → dataset       │
   └──────────────────────────────────────────────┘
```

Discovery is read-only. AgentGuard opens sockets and reads config files; it never writes to a discovered agent, and it never reads a credential value.

## Quick Start

```bash
pip install -e .

# Dry run — scan and score, write nothing
agentguard --no-datahub

# Publish the inventory to DataHub
export DATAHUB_URL=http://localhost:8080
export DATAHUB_TOKEN=your-token
agentguard

# Or point at DataHub directly
agentguard --url http://datahub-gms.internal:8080 --token "$TOKEN"
```

| Flag | Description |
|---|---|
| `--url` | DataHub GMS URL (default: `$DATAHUB_URL`, else `http://localhost:8080`) |
| `--token` | DataHub access token (default: `$DATAHUB_TOKEN`) |
| `--output` | Report path (default: `scan_output.json`) |
| `--no-datahub` | Scan and score without writing |

AgentGuard **exits 1 when any critical asset is found**, so it drops into CI as a gate:

```yaml
- name: Agent fleet audit
  run: agentguard --no-datahub
```

If DataHub is unreachable, AgentGuard warns and completes the scan — the local report is still written.

## What gets discovered

| Source | What it finds |
|---|---|
| `~/.claude/settings.json`, `.mcp.json`, `.cursorrules` | Declared MCP servers, their tools, and auth configuration |
| Ports 3000, 5000, 8080, 8888, 9000 | Undeclared MCP servers, confirmed live via `GET /health` or `/mcp` |
| `ps aux` | Claude, LangChain, AutoGen, CrewAI, Ollama, OpenAI agent processes |
| `docker ps` | Containerized AI workloads |
| `.env` in cwd and `~/projects/*` | `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `LANGCHAIN_*`, `AGENT_*` |

**Credential names only — never values.** AgentGuard records that `ANTHROPIC_API_KEY` is present in a given file. The secret itself is never read into memory, never written to the report, and never sent to DataHub.

Every asset resolves to one of three states:

- **ACTIVE** — found and responding.
- **ORPHANED** — declared in a config, but not responding. The high-value finding.
- **UNKNOWN** — credentials present, no running process matched.

## Risk scoring

Each asset scores 0–100 by additive signal:

| Signal | Points | Rationale |
|---|---|---|
| No authentication | +40 | Anything on the network can drive the agent |
| Write / delete / exec tools | +25 | Actions are irreversible |
| ORPHANED | +20 | Endpoint is claimable |
| UNKNOWN | +10 | Unattributed credentials |
| Shell / command tools | +8 | **LLM01** Prompt Injection |
| File / database read tools | +4 | **LLM06** Sensitive Information Disclosure |
| More than 5 tools | +3 | **LLM08** Excessive Agency |

| Tier | Score |
|---|---|
| critical | ≥ 75 |
| high | ≥ 50 |
| medium | ≥ 25 |
| low | < 25 |

Findings are tagged against the **OWASP LLM Top 10**, so agent risk reports in the vocabulary your security team already reviews.

## EU AI Act compliance

The Act applies from **2 August 2026**. AgentGuard writes the fields its obligations depend on directly onto each DataHub entity, as `customProperties`:

| Property | Maps to |
|---|---|
| `agentguard.eu_ai_act.owner` | Art. 26 — accountable human oversight |
| `agentguard.eu_ai_act.data_access_scope` | Art. 9 — risk management, documented scope |
| `agentguard.eu_ai_act.disclosure_compliant` | Art. 50 — transparency obligations |
| `agentguard.eu_ai_act.risk_category` | Annex III — high / limited / minimal risk |
| `agentguard.owasp_tags` | OWASP LLM Top 10 findings |
| `agentguard.last_seen` | Art. 12 — record keeping |

Risk tiers map to the Act's categories: `critical`/`high` → **high-risk**, `medium` → **limited-risk**, `low` → **minimal-risk**.

See [`examples/eu_ai_act_compliance.json`](examples/eu_ai_act_compliance.json) for a full report.

## Architecture

```
src/agentguard/
├── main.py                  CLI: scan → score → report → publish → lineage
├── scanner/
│   ├── mcp_scanner.py       Config parsing + port discovery + liveness probe
│   └── agent_scanner.py     Processes, containers, env credentials
├── risk/
│   └── scorer.py            0-100 scoring, tiers, OWASP tagging
└── datahub/
    ├── writer.py            mlModel + tags + ownership + EU AI Act properties
    ├── lineage.py           agent → mcp_server → dataset upstream lineage
    └── skill.py             AgentGuardSkill, reusable from a DataHub agent
```

Assets land in DataHub as `mlModel` entities:

```
urn:li:mlModel:(urn:li:dataPlatform:mcp,{name},PROD)
```

tagged `agentguard-discovered`, `risk-{tier}`, and `orphaned` where applicable — so an agent fleet is searchable, ownable, and lineage-traced alongside every other asset in the catalog.

### Use as a DataHub skill

```python
from agentguard.datahub.skill import AgentGuardSkill

result = AgentGuardSkill().run({"url": "http://localhost:8080", "token": token})
print(result["summary"])
```

## Examples

Sample outputs, readable without running a scan:

- [`examples/scan_output.json`](examples/scan_output.json) — a 4-asset fleet scan
- [`examples/eu_ai_act_compliance.json`](examples/eu_ai_act_compliance.json) — per-asset compliance fields
- [`examples/risk_report.md`](examples/risk_report.md) — risk summary with remediation steps

## Requirements

Python 3.10+ · `acryl-datahub>=0.14` · `requests>=2.31`

## License

Apache-2.0
