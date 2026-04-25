"""Deterministic classification rules for high-confidence alert patterns."""
from ..models import Alert, Severity, DecisionSource


class RulesEngine:
    """Classify known alert types before escalating ambiguous cases to the LLM."""

    KNOWN_CRITICAL_PROCESSES = [
        "mimikatz", "cobalt strike", "meterpreter", "bloodhound",
        "lazagne", "rubeus", "sharphound", "empire",
    ]

    KNOWN_FP_PATTERNS = [
        {"field": "source_tool", "contains": "Nessus", "alert_type_contains": "scan"},
        {"field": "source_tool", "contains": "Qualys", "alert_type_contains": "scan"},
        {"field": "alert_type", "equals": "ScheduledScan"},
        {"field": "description", "contains": "scheduled vulnerability scan"},
    ]

    def evaluate(self, alert: Alert) -> dict | None:
        proc = (alert.process_name or "").lower()
        desc = alert.description.lower()
        for tool in self.KNOWN_CRITICAL_PROCESSES:
            if tool in proc or tool in desc:
                return {
                    "severity": Severity.CRITICAL.value,
                    "confidence": 0.99,
                    "mitre_technique": "T1003.001" if "mimikatz" in tool else "T1059",
                    "mitre_name": f"Known malicious tool: {tool}",
                    "attack_stage": "credential_access",
                    "reasoning": f"Deterministic rule matched known attack tool: {tool}.",
                    "decision_source": DecisionSource.DETERMINISTIC.value,
                }

        for pattern in self.KNOWN_FP_PATTERNS:
            if self._match_pattern(alert, pattern):
                return {
                    "severity": Severity.FALSE_POSITIVE.value,
                    "confidence": 0.97,
                    "mitre_technique": "N/A",
                    "mitre_name": "Known benign activity",
                    "attack_stage": "none",
                    "reasoning": "Deterministic rule matched a known benign scanner pattern.",
                    "decision_source": DecisionSource.DETERMINISTIC.value,
                }

        if "certificate" in desc and ("expir" in desc or "renew" in desc):
            return {
                "severity": Severity.LOW.value,
                "confidence": 0.96,
                "mitre_technique": "N/A",
                "mitre_name": "Certificate Maintenance",
                "attack_stage": "none",
                "reasoning": "Deterministic rule: Certificate lifecycle event, not a threat.",
                "decision_source": DecisionSource.DETERMINISTIC.value,
            }

        return None

    def _match_pattern(self, alert: Alert, pattern: dict) -> bool:
        field_val = ""
        if pattern["field"] == "source_tool":
            field_val = alert.source_tool.lower()
        elif pattern["field"] == "alert_type":
            field_val = alert.alert_type.lower()
        elif pattern["field"] == "description":
            field_val = alert.description.lower()

        if "contains" in pattern and pattern["contains"].lower() in field_val:
            if "alert_type_contains" in pattern:
                return pattern["alert_type_contains"].lower() in alert.alert_type.lower()
            return True
        if "equals" in pattern and field_val == pattern["equals"].lower():
            return True
        return False
