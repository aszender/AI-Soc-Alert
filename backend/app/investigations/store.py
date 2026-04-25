"""Shared investigation storage.

This is intentionally small and process-local for now, but all callers go
through this module so replacing it with SQLite/Postgres does not touch the API
or MCP tool layers.
"""
from threading import RLock

from ..models import InvestigationReport


class InvestigationStore:
    def __init__(self):
        self._lock = RLock()
        self._items: dict[str, InvestigationReport] = {}

    def save(self, report: InvestigationReport) -> InvestigationReport:
        with self._lock:
            self._items[report.id] = report
        return report

    def get(self, investigation_id: str) -> InvestigationReport | None:
        with self._lock:
            return self._items.get(investigation_id)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


store = InvestigationStore()
