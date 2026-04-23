from backend.app.agents.supervisor import SupervisorAgent
from backend.app.core.llm_client import LLMClient
from backend.app.models import Alert


def test_llm_client_keeps_token_metadata_for_callers():
    client = LLMClient()
    client.is_demo = True

    result = client.call(
        "You are a Tier 2 SOC analyst specializing in alert triage. Classify the alert.",
        "Impossible travel followed by powershell encoded command and 2.3GB exfiltration.",
    )

    assert result["_tokens"] > 0
    assert client.get_stats()["total_tokens"] == result["_tokens"]


class FakeLLM:
    def __init__(self):
        self.responses = [
            {
                "severity": "critical",
                "confidence": 0.9,
                "mitre_technique": "T1078",
                "mitre_name": "Valid Accounts",
                "reasoning": "Suspicious chained activity.",
                "_tokens": 111,
            },
            {
                "results": [],
                "fallback": True,
                "error": "invalid enrichment json",
                "_tokens": 222,
            },
            {
                "steps": [],
                "raw_response": "not json",
                "_tokens": 333,
            },
        ]

    def call(self, system_prompt, user_message, temperature=0.0, max_tokens=2000):
        return self.responses.pop(0)


def test_supervisor_records_tokens_and_llm_diagnostics():
    supervisor = SupervisorAgent(FakeLLM())
    alert = Alert(
        source_tool="Defender",
        description="Impossible travel followed by encoded PowerShell and outbound transfer.",
        source_ip="203.0.113.10",
        hostname="FIN-LT-023",
        process_name="powershell.exe",
    )

    report = supervisor.investigate(alert)

    assert report.total_llm_calls == 3
    assert report.total_tokens_used == 666
    assert report.trace[2]["tokens_used"] == 111
    assert report.trace[3]["fallback"] is True
    assert report.trace[3]["error"] == "invalid enrichment json"
    assert report.trace[4]["raw_response"] is True
