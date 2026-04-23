"""Enrichment Agent — Gathers threat intelligence for IOCs."""
from ..core.llm_client import LLMClient
from ..models import Alert

SYSTEM_PROMPT = """You are a threat intel analyst. Synthesize IOC enrichment data.
RESPOND IN JSON: {"indicators_checked":N,"results":[{"indicator":"","type":"ip|hash",
"is_malicious":bool,"confidence":0-1,"source":"","details":""}],
"overall_threat_level":"critical|high|medium|low|benign"}"""


class EnrichmentAgent:
    def __init__(self, llm: LLMClient):
        self.llm = llm

    def enrich(self, alert: Alert) -> dict:
        iocs = []
        if alert.source_ip:
            iocs.append(f"IP: {alert.source_ip}")
        if alert.destination_ip:
            iocs.append(f"IP: {alert.destination_ip}")
        if h := alert.raw_event.get("file_hash"):
            iocs.append(f"Hash: {h}")
        msg = f"Alert: {alert.description}\nIOCs to enrich: {', '.join(iocs) if iocs else 'none'}"
        return self.llm.call(SYSTEM_PROMPT, msg)
