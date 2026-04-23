"""Response Agent — Generates context-aware remediation playbooks at runtime."""
import json
from ..core.llm_client import LLMClient
from ..models import Alert

SYSTEM_PROMPT = """You are an incident response specialist.
Generate a response playbook. Actions that MODIFY systems must have requires_approval: true.
RESPOND IN JSON:
{"playbook_name":"","generated_at_runtime":true,"urgency":"immediate|within_1_hour|within_24_hours",
"steps":[{"order":N,"action":"","target":"","risk_level":"read_only|low_risk|high_risk|critical",
"requires_approval":bool,"reason":"","tool":""}]}"""


class ResponseAgent:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def generate_playbook(self, alert: Alert, triage: dict, enrichment: dict) -> dict:
        msg = f"""ALERT: {alert.description}
Host: {alert.hostname} | User: {alert.username} | IP: {alert.source_ip}
TRIAGE: severity={triage.get('severity')}, technique={triage.get('mitre_technique')}
ENRICHMENT: {json.dumps(enrichment, default=str)[:1500]}
TOOLS: CrowdStrike (endpoint), Palo Alto (firewall), Azure AD (identity), Splunk (SIEM)"""
        return self.llm.call(SYSTEM_PROMPT, msg)
