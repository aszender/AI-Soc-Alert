# AI SOC Investigator

AI SOC Investigator is a multi-agent incident investigation platform for security alerts. It combines deterministic detection logic, governed LLM reasoning, enrichment, response playbook generation, human approval gates, and MCP tool exposure behind a FastAPI service.

The project is structured as an AI engineering system rather than a prompt-only prototype. The core design separates orchestration, model access, guardrails, governance, persistence, API delivery, MCP delivery, and evaluation so each layer can be tested and replaced independently.

## Architecture

```text
Security alert
    |
    v
FastAPI / MCP tool interface
    |
    v
Investigation service
    |
    v
Supervisor agent
    |
    +--> Input guardrails
    +--> Deterministic rules engine
    +--> LLM triage agent
    +--> Enrichment agent
    +--> Response agent
    +--> Output guardrails
    +--> HITL approval workflow
    |
    v
Investigation report, trace, recommendations, metrics
```

## Core Capabilities

- Multi-agent alert investigation coordinated by a supervisor agent.
- Deterministic rules for high-confidence security patterns before LLM escalation.
- LLM triage with MITRE ATT&CK mapping, confidence scoring, and structured JSON outputs.
- Threat enrichment abstraction for IPs, domains, and hashes.
- Response playbook generation with action risk classification.
- Human-in-the-loop approval gates for high-risk or destructive actions.
- Input guardrails for prompt injection and oversized payloads.
- Output guardrails for hallucinated indicators, severity downgrades, invalid confidence, and incomplete actions.
- Token and call budget enforcement per investigation.
- Structured JSON logging with trace IDs, latency, token usage, and decision source.
- FastAPI endpoints for application integration.
- MCP server exposing investigation tools to AI clients such as VS Code, Claude Desktop, and MCP Inspector.
- Evaluation harness with golden alerts for regression testing investigation quality.

## Repository Layout

```text
backend/app/api/              FastAPI routes
backend/app/agents/           Triage, enrichment, response, and supervisor agents
backend/app/core/             Configuration, LLM client, logging, deterministic rules
backend/app/evals/            Golden-alert evaluation harness
backend/app/governance/       Budgets, permissions, audit log, human approvals
backend/app/guardrails/       Input and output safety controls
backend/app/integrations/     MCP server and connector abstractions
backend/app/investigations/   Shared investigation service and store
backend/tests/                API, governance, guardrail, observability, and MCP tests
```

## Runtime Interfaces

### FastAPI

The HTTP API is intended for service-to-service or dashboard integration.

```bash
uv run uvicorn main:app --reload
```

Primary endpoints:

```text
POST /alerts/investigate
GET  /investigations/{investigation_id}
GET  /approvals/pending
POST /approvals/{request_id}/approve
POST /approvals/{request_id}/reject
GET  /health
```

### MCP Server

The MCP server exposes the investigation system as tools for AI hosts.

```bash
uv run soc-mcp-server
```

Available MCP tools:

```text
investigate_alert
lookup_threat_intel
get_investigation
```

Example VS Code workspace configuration:

```json
{
  "servers": {
    "soc-investigator": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/ai-soc-investigator",
        "run",
        "soc-mcp-server"
      ]
    }
  }
}
```

Save this as `.vscode/mcp.json`, then use `MCP: List Servers` from the VS Code command palette and start `soc-investigator`.

## Investigation Flow

1. The API or MCP layer receives an alert and validates the request.
2. The investigation service builds a domain `Alert` and delegates to the supervisor.
3. Input guardrails block prompt injection and malformed oversized alert text before model access.
4. The rules engine handles known patterns such as credential dumping tools, scheduled scanner activity, and certificate lifecycle events.
5. Ambiguous alerts are escalated to the triage agent for severity classification, MITRE mapping, confidence scoring, and rationale generation.
6. The enrichment agent checks relevant indicators and normalizes results into the report.
7. The response agent generates a playbook with action risk levels and approval requirements.
8. Governance controls apply token budgets, least-privilege policy, and human approval gates.
9. Output guardrails validate the report before returning it to the caller.
10. The final report includes severity, confidence, evidence, enrichment, recommended actions, trace entries, token usage, and latency.

## Configuration

Configuration is environment-driven.

```bash
cp .env.example .env
```

Important settings:

```text
OPENAI_API_KEY
LLM_MODEL
LLM_TEMPERATURE
MAX_TOKENS_PER_INVESTIGATION
MAX_LLM_CALLS_PER_INVESTIGATION
MAX_TOOL_CALLS_PER_INVESTIGATION
LOG_LEVEL
DB_PATH
```

When `OPENAI_API_KEY=demo-key`, the system uses deterministic local fixtures for repeatable development and CI behavior. Set a real key to exercise live LLM calls.

## Testing

Run the full test suite:

```bash
uv run pytest
```

Run the evaluation harness:

```bash
uv run python -m backend.app.evals.evaluate
```

Run MCP-focused tests:

```bash
uv run pytest backend/tests/test_mcp_server.py
```

## Docker

Build and run the API service:

```bash
docker compose up --build
```

The API is exposed on port `8000`.

## Engineering Notes

The current store is process-local and intentionally isolated behind `backend/app/investigations/store.py`. Replacing it with SQLite, Postgres, or a queue-backed workflow store does not require changing the API or MCP tool layer.

The threat-intel implementation uses an injectable provider interface. Production deployment should wire this to VirusTotal, AbuseIPDB, MISP, a commercial TIP, or an internal intelligence service.

The system is designed around bounded autonomy: model calls are budgeted, tool outputs are validated, high-risk actions require approval, and deterministic rules are preferred when confidence is high.
