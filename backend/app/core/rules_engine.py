"""
Deterministic Rules Engine — Handles known patterns WITHOUT calling the LLM.

This is critical for production AI systems:
- Known malware (mimikatz, cobalt strike) → always critical, no LLM needed
- Scheduled scans → always false positive, no LLM needed
- Certificate expiry → always low/maintenance, no LLM needed

WHY: Deterministic rules are faster (0ms vs 2000ms), cheaper ($0 vs $0.03),
and 100% reliable (same input = same output every time).

The LLM handles NOVEL or AMBIGUOUS alerts that don't match any rule.

D3 Morpheus tracks the deterministic-to-LLM ratio over time.
As patterns become well-understood, they graduate from LLM to rules.
"""
from ..models import Alert, Severity, DecisionSource


class RulesEngine:
    """
    Pattern-matching rules for known alert types.
    Returns a classification if matched, None if the alert needs LLM analysis.
    """

    # Known malicious tools — always critical, no ambiguity
    KNOWN_CRITICAL_PROCESSES = [
        "mimikatz", "cobalt strike", "meterpreter", "bloodhound",
        "lazagne", "rubeus", "sharphound", "empire",
    ]

    # Known false positive sources
    KNOWN_FP_PATTERNS = [
        {"field": "source_tool", "contains": "Nessus", "alert_type_contains": "scan"},
        {"field": "source_tool", "contains": "Qualys", "alert_type_contains": "scan"},
        {"field": "alert_type", "equals": "ScheduledScan"},
        {"field": "description", "contains": "scheduled vulnerability scan"},
    ]

    def evaluate(self, alert: Alert) -> dict | None:
        """
        Try to classify the alert using deterministic rules.

        Returns:
            dict with classification if a rule matches, or None if LLM is needed.
        """
        # Rule 1: Known critical tools
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
                    "reasoning": f"Deterministic rule: '{tool}' is a known attack tool. "
                                 f"No LLM analysis needed.",
                    "decision_source": DecisionSource.DETERMINISTIC.value,
                }

        # Rule 2: Known false positives (scheduled scans)
        for pattern in self.KNOWN_FP_PATTERNS:
            if self._match_pattern(alert, pattern):
                return {
                    "severity": Severity.FALSE_POSITIVE.value,
                    "confidence": 0.97,
                    "mitre_technique": "N/A",
                    "mitre_name": "Known benign activity",
                    "attack_stage": "none",
                    "reasoning": f"Deterministic rule: Matches known false positive pattern.",
                    "decision_source": DecisionSource.DETERMINISTIC.value,
                }

        # Rule 3: Certificate expiry — operational, not security
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

        # No rule matched → needs LLM
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
