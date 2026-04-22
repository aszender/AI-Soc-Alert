"""Audit log — immutable record of every agent decision."""
from datetime import datetime, timezone
from ..core.logging import get_trace_id

_logs: list[dict] = []


def log_action(agent_id: str, action: str, details: dict | None = None):
    _logs.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "trace_id": get_trace_id(),
        "agent": agent_id,
        "action": action,
        "details": details or {},
    })


def get_logs(trace_id: str | None = None) -> list[dict]:
    if trace_id:
        return [l for l in _logs if l["trace_id"] == trace_id]
    return list(_logs)


def clear():
    _logs.clear()
