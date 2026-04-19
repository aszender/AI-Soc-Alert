"""
LLM API client with retry, token tracking, and demo mode.

Wraps the LLM so the rest of the app doesn't care which provider
is behind it. Swap OpenAI for Azure OpenAI or Anthropic without
changing any agent code.
"""
import json
import time
from typing import Optional
from .config import settings
from .logging import structured_log, Timer


class LLMClient:
    def __init__(self):
        self.model = settings.LLM_MODEL
        self.is_demo = settings.is_demo_mode
        self.call_count = 0
        self.token_count = 0

    def call(
        self,
        system_prompt: str,
        user_message: str,
        temperature: float = 0.0,
        max_tokens: int = 2000,
    ) -> dict:
        self.call_count += 1

        with Timer() as t:
            if self.is_demo:
                result = self._demo_response(system_prompt, user_message)
            else:
                result = self._api_call(system_prompt, user_message, temperature, max_tokens)

        structured_log(
            "INFO", "llm_call",
            agent_id="llm_client",
            tokens_used=result.get("_tokens", 0),
            latency_ms=t.ms,
        )
        self.token_count += result.pop("_tokens", 0)
        return result

    def _api_call(self, system_prompt, user_message, temperature, max_tokens, retries=3):
        import openai
        client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        for attempt in range(retries):
            try:
                resp = client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                content = resp.choices[0].message.content
                tokens = resp.usage.total_tokens
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = {"raw_response": content}
                parsed["_tokens"] = tokens
                return parsed
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    return {"error": str(e), "fallback": True, "_tokens": 0}

    # ── Demo Responses ──

    def _demo_response(self, system_prompt: str, user_message: str) -> dict:
        sp = system_prompt.lower()
        um = user_message.lower()
        if "triage" in sp or "classify" in sp:
            return self._demo_triage(um)
        if "enrich" in sp or "threat" in sp:
            return self._demo_enrichment(um)
        if "playbook" in sp or "response" in sp or "remediat" in sp:
            return self._demo_playbook(um)
        if "verify" in sp or "critic" in sp:
            return {"valid": True, "issues": [], "_tokens": 80}
        return self._demo_triage(um)

    def _demo_triage(self, msg: str) -> dict:
        if any(w in msg for w in ["mimikatz", "lsass", "credential dump"]):
            return {"severity": "critical", "confidence": 0.95, "mitre_technique": "T1003.001",
                    "mitre_name": "OS Credential Dumping: LSASS Memory", "attack_stage": "credential_access",
                    "reasoning": "Mimikatz detected — active credential theft indicating compromise.", "_tokens": 120}
        if any(w in msg for w in ["brute force", "failed login", "failed ssh"]):
            return {"severity": "medium", "confidence": 0.82, "mitre_technique": "T1110.001",
                    "mitre_name": "Brute Force: Password Guessing", "attack_stage": "credential_access",
                    "reasoning": "Multiple failed logins from single source. Check if any succeeded.", "_tokens": 100}
        if any(w in msg for w in ["exfiltration", "large download", "data transfer", "2.3gb"]):
            return {"severity": "high", "confidence": 0.88, "mitre_technique": "T1041",
                    "mitre_name": "Exfiltration Over C2 Channel", "attack_stage": "exfiltration",
                    "reasoning": "Large outbound transfer during non-business hours to external IP.", "_tokens": 110}
        if any(w in msg for w in ["certificate", "expir", "ssl"]):
            return {"severity": "low", "confidence": 0.96, "mitre_technique": "N/A",
                    "mitre_name": "Certificate Maintenance", "attack_stage": "none",
                    "reasoning": "Certificate expiry is operational, not a security threat.", "_tokens": 70}
        if any(w in msg for w in ["phish", "suspicious email", "malicious link"]):
            return {"severity": "high", "confidence": 0.87, "mitre_technique": "T1566.001",
                    "mitre_name": "Phishing: Spearphishing Attachment", "attack_stage": "initial_access",
                    "reasoning": "Phishing attempt detected with suspicious attachment or link.", "_tokens": 100}
        if any(w in msg for w in ["impossible travel", "geo anomaly"]):
            return {"severity": "high", "confidence": 0.84, "mitre_technique": "T1078",
                    "mitre_name": "Valid Accounts", "attack_stage": "initial_access",
                    "reasoning": "Login from two distant locations within impossible timeframe.", "_tokens": 95}
        if any(w in msg for w in ["powershell", "encoded command", "invoke-expression"]):
            return {"severity": "medium", "confidence": 0.75, "mitre_technique": "T1059.001",
                    "mitre_name": "PowerShell", "attack_stage": "execution",
                    "reasoning": "Suspicious PowerShell execution. Needs context to determine intent.", "_tokens": 90}
        if any(w in msg for w in ["vulnerability scan", "nessus", "qualys", "scheduled scan"]):
            return {"severity": "false_positive", "confidence": 0.97, "mitre_technique": "N/A",
                    "mitre_name": "Scheduled Vulnerability Scan", "attack_stage": "none",
                    "reasoning": "Known scheduled scan from authorized vulnerability scanner.", "_tokens": 60}
        return {"severity": "medium", "confidence": 0.60, "mitre_technique": "T1059",
                "mitre_name": "Command and Scripting Interpreter", "attack_stage": "execution",
                "reasoning": "Requires further investigation. Low confidence.", "_tokens": 85}

    def _demo_enrichment(self, msg: str) -> dict:
        return {
            "indicators_checked": 2,
            "results": [
                {"indicator": "45.33.32.156", "type": "ip", "is_malicious": True,
                 "confidence": 0.91, "source": "VirusTotal",
                 "details": "Flagged by 12/90 vendors. Associated with Cobalt Strike C2."},
                {"indicator": "45.33.32.156", "type": "ip", "is_malicious": True,
                 "confidence": 0.87, "source": "AbuseIPDB",
                 "details": "Reported 47 times. Categories: SSH brute force, web attack."},
            ],
            "overall_threat_level": "high",
            "_tokens": 130,
        }

    def _demo_playbook(self, msg: str) -> dict:
        return {
            "playbook_name": "Credential Theft Response",
            "generated_at_runtime": True,
            "urgency": "immediate",
            "steps": [
                {"order": 1, "action": "isolate_endpoint", "target": "WORKSTATION-042",
                 "risk_level": "critical", "requires_approval": True,
                 "reason": "Prevent lateral movement from compromised host",
                 "tool": "CrowdStrike Falcon"},
                {"order": 2, "action": "disable_user_account", "target": "jsmith",
                 "risk_level": "high_risk", "requires_approval": True,
                 "reason": "Compromised credentials must be disabled",
                 "tool": "Azure AD"},
                {"order": 3, "action": "block_ip", "target": "45.33.32.156",
                 "risk_level": "high_risk", "requires_approval": True,
                 "reason": "Block known C2 server at perimeter",
                 "tool": "Palo Alto Firewall"},
                {"order": 4, "action": "scan_subnet", "target": "10.0.15.0/24",
                 "risk_level": "read_only", "requires_approval": False,
                 "reason": "Check for lateral movement evidence",
                 "tool": "CrowdStrike Falcon"},
                {"order": 5, "action": "force_password_reset", "target": "jsmith",
                 "risk_level": "high_risk", "requires_approval": True,
                 "reason": "Rotate all potentially exposed credentials",
                 "tool": "Azure AD"},
            ],
            "_tokens": 200,
        }

    def get_stats(self) -> dict:
        return {"total_calls": self.call_count, "total_tokens": self.token_count}
