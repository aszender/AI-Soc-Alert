"""
Structured logging with trace_id, latency, and observability fields.

Every log entry includes:
- trace_id: links all steps of one investigation together
- agent_id: which agent produced the log
- latency_ms: how long the operation took
- decision_source: "deterministic" or "llm"
- tokens_used: LLM token consumption

This is what production AI systems need for debugging and monitoring.
"""
import json
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

_trace_id: ContextVar[str] = ContextVar("trace_id", default="")


def new_trace_id() -> str:
    tid = uuid.uuid4().hex[:12]
    _trace_id.set(tid)
    return tid


def get_trace_id() -> str:
    return _trace_id.get() or new_trace_id()


class Timer:
    """Context manager to measure latency."""
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.ms = round((time.perf_counter() - self._start) * 1000, 2)


def structured_log(
    level: str,
    event: str,
    agent_id: str = "system",
    decision_source: str = "",
    tokens_used: int = 0,
    latency_ms: float = 0.0,
    extra: dict[str, Any] | None = None,
):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "trace_id": get_trace_id(),
        "agent": agent_id,
        "event": event,
    }
    if decision_source:
        entry["decision_source"] = decision_source
    if tokens_used:
        entry["tokens_used"] = tokens_used
    if latency_ms:
        entry["latency_ms"] = latency_ms
    if extra:
        entry.update(extra)
    # In production: ship to ELK / Datadog / Splunk
    print(json.dumps(entry))
