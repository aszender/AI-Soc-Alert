"""Base connector with circuit breaker and health monitoring."""
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ..models import Alert


class BaseConnector(ABC):
    def __init__(self, name: str, api_url: str = ""):
        self.name = name
        self.api_url = api_url
        self.healthy = True
        self.failures = 0
        self.threshold = 5
        self.last_success: datetime | None = None

    def fetch_alerts(self, since: datetime) -> list[Alert]:
        if self.failures >= self.threshold: #circuit breaker: if too many failures, skip fetching and return empty list
            return []
        try:
            raw = self._fetch_raw(since)
            self.failures = 0
            self.last_success = datetime.now(timezone.utc)
            self.healthy = True
            return [self.normalize(r) for r in raw]
        except Exception:
            self.failures += 1
            if self.failures >= self.threshold:
                self.healthy = False
            return []

    @abstractmethod
    def _fetch_raw(self, since: datetime) -> list[dict]: ...

    @abstractmethod
    def normalize(self, raw: dict) -> Alert: ...

    def health(self) -> dict:
        return {"name": self.name, "healthy": self.healthy,
                "failures": self.failures,
                "last_success": self.last_success.isoformat() if self.last_success else None}
