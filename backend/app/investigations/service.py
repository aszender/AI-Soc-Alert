"""Application service for alert investigations."""
from ..agents.supervisor import SupervisorAgent
from ..core.llm_client import LLMClient
from ..models import Alert, InvestigationReport
from .store import store


class InvestigationService:
    def __init__(
        self,
        llm: LLMClient | None = None,
        supervisor: SupervisorAgent | None = None,
    ):
        self.llm = llm or LLMClient()
        self.supervisor = supervisor or SupervisorAgent(self.llm)

    def investigate(self, alert: Alert) -> InvestigationReport:
        report = self.supervisor.investigate(alert)
        store.save(report)
        return report

    def get(self, investigation_id: str) -> InvestigationReport | None:
        return store.get(investigation_id)


service = InvestigationService()
