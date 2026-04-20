"""
Output Guardrails — Safety checks AFTER the LLM generates a response.
"""
import re
from ..models import Alert, InvestigationReport


class OutputGuard:
    def check(self, report: InvestigationReport, alert: Alert) -> tuple[bool, list[str]]:
        issues: list[str] = []

        # 1. Hallucinated IPs
        report_ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", report.attack_narrative))
        alert_ips = set()
        if alert.source_ip:
            alert_ips.add(alert.source_ip)
        if alert.destination_ip:
            alert_ips.add(alert.destination_ip)
        for ip_str in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", str(alert.raw_event)):
            alert_ips.add(ip_str)
        hallucinated = report_ips - alert_ips
        if hallucinated:
            issues.append(f"Hallucinated IPs not in alert: {hallucinated}")

        # 2. Suspicious severity downgrade
        raw_sev = alert.raw_event.get("severity", "")
        if isinstance(raw_sev, int) and raw_sev > 80:
            if report.severity.value in ("low", "false_positive"):
                issues.append(f"Suspicious downgrade: vendor severity={raw_sev} but AI says {report.severity.value}")

        # 3. Confidence range
        if not 0.0 <= report.confidence <= 1.0:
            issues.append(f"Invalid confidence: {report.confidence}")

        # 4. Actions without targets
        for act in report.recommended_actions:
            if not act.target:
                issues.append(f"Action '{act.action}' missing target")

        return len(issues) == 0, issues
