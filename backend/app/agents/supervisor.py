"""
Supervisor Agent — Orchestrates multi-agent investigation.

Flow: Input Guardrails → Rules Engine → (if no rule) LLM Triage → Enrichment → Response → Output Guardrails
"""
from datetime import datetime, timezone

from ..models import (Alert, InvestigationReport, Severity, DecisionSource,
                       RecommendedAction, ActionRisk, EnrichmentResult)
from ..core.llm_client import LLMClient
from ..core.rules_engine import RulesEngine
from ..core.logging import new_trace_id, get_trace_id, structured_log, Timer
from ..guardrails.input_guard import InputGuard
from ..guardrails.output_guard import OutputGuard
from ..governance import audit, hitl
from ..governance.budget import BudgetGovernor
from .triage_agent import TriageAgent
from .enrichment_agent import EnrichmentAgent
from .response_agent import ResponseAgent


class SupervisorAgent:
    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.rules = RulesEngine()
        self.triage = TriageAgent(llm)
        self.enrichment = EnrichmentAgent(llm)
        self.response = ResponseAgent(llm)
        self.input_guard = InputGuard()
        self.output_guard = OutputGuard()

    def investigate(self, alert: Alert) -> InvestigationReport:
        trace_id = new_trace_id()
        budget = BudgetGovernor()
        report = InvestigationReport(alert_id=alert.id)
        trace = []

        with Timer() as total_timer:
            # ── 1. INPUT GUARDRAILS ──
            safe, reason = self.input_guard.check(alert.description)
            trace.append({"step": "input_guardrails", "passed": safe, "detail": reason})
            audit.log_action("supervisor", "input_guardrails", {"passed": safe, "reason": reason})

            if not safe:
                report.requires_human_review = True
                report.attack_narrative = f"Blocked by input guardrails: {reason}"
                report.guardrail_blocks += 1
                report.trace = trace
                structured_log("WARN", "guardrail_block", agent_id="supervisor",
                               extra={"reason": reason})
                return report

            # ── 2. DETERMINISTIC RULES ──
            with Timer() as rules_timer:
                rule_result = self.rules.evaluate(alert)

            if rule_result:
                report.severity = Severity(rule_result["severity"])
                report.confidence = rule_result["confidence"]
                report.mitre_technique = rule_result["mitre_technique"]
                report.mitre_name = rule_result.get("mitre_name", "")
                report.attack_narrative = rule_result["reasoning"]
                report.decision_source = DecisionSource.DETERMINISTIC
                report.requires_human_review = report.severity == Severity.CRITICAL
                trace.append({"step": "rules_engine", "matched": True,
                              "latency_ms": rules_timer.ms})
                audit.log_action("supervisor", "deterministic_match",
                                 {"severity": report.severity.value})
                structured_log("INFO", "deterministic_match", agent_id="rules_engine",
                               decision_source="deterministic", latency_ms=rules_timer.ms)
            else:
                trace.append({"step": "rules_engine", "matched": False,
                              "latency_ms": rules_timer.ms})

                # ── 3. LLM TRIAGE ──
                if budget.can_call():
                    with Timer() as triage_timer:
                        triage_result = self.triage.classify(alert)
                    budget.record(triage_result.get("_tokens", 0))

                    report.severity = Severity(triage_result.get("severity", "medium"))
                    report.confidence = triage_result.get("confidence", 0.0)
                    report.mitre_technique = triage_result.get("mitre_technique", "")
                    report.mitre_name = triage_result.get("mitre_name", "")
                    report.attack_narrative = triage_result.get("reasoning", "")
                    report.decision_source = DecisionSource.LLM

                    if report.confidence < 0.7:
                        report.requires_human_review = True

                    trace.append({"step": "triage", "agent": "triage_agent",
                                  "severity": report.severity.value,
                                  "confidence": report.confidence,
                                  "latency_ms": triage_timer.ms})
                    audit.log_action("triage", "classify",
                                     {"severity": report.severity.value,
                                      "confidence": report.confidence})

            # Close false positives early
            if report.severity == Severity.FALSE_POSITIVE and report.confidence > 0.85:
                report.requires_human_review = False
                report.trace = trace
                report.total_llm_calls = budget.calls
                report.total_tokens_used = budget.tokens
                return report

            # ── 4. ENRICHMENT ──
            if budget.can_call() and report.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                with Timer() as enrich_timer:
                    enrich_data = self.enrichment.enrich(alert)
                budget.record(enrich_data.get("_tokens", 0))

                for r in enrich_data.get("results", []):
                    report.enrichment_results.append(EnrichmentResult(
                        indicator=r.get("indicator", ""),
                        indicator_type=r.get("type", ""),
                        source=r.get("source", ""),
                        is_malicious=r.get("is_malicious"),
                        confidence=r.get("confidence", 0.0),
                        details=r.get("details", ""),
                    ))
                trace.append({"step": "enrichment", "agent": "enrichment_agent",
                              "indicators": len(report.enrichment_results),
                              "latency_ms": enrich_timer.ms})
                audit.log_action("enrichment", "enrich",
                                 {"indicators": len(report.enrichment_results)})

            # ── 5. RESPONSE PLAYBOOK ──
            if budget.can_call() and report.severity in (Severity.CRITICAL, Severity.HIGH):
                with Timer() as resp_timer:
                    playbook = self.response.generate_playbook(
                        alert,
                        {"severity": report.severity.value,
                         "mitre_technique": report.mitre_technique},
                        {"results": [r.model_dump() for r in report.enrichment_results]}
                    )
                budget.record(playbook.get("_tokens", 0))

                for step in playbook.get("steps", []):
                    risk = step.get("risk_level", "read_only")
                    try:
                        risk_enum = ActionRisk(risk)
                    except ValueError:
                        risk_enum = ActionRisk.HIGH_RISK
                    action = RecommendedAction(
                        action=step["action"],
                        target=step["target"],
                        reason=step.get("reason", ""),
                        risk_level=risk_enum,
                        requires_approval=step.get("requires_approval", True),
                    )
                    report.recommended_actions.append(action)

                    # Submit high-risk actions for HITL approval
                    if action.requires_approval:
                        hitl.request_approval(action, report.id)

                trace.append({"step": "response", "agent": "response_agent",
                              "actions": len(report.recommended_actions),
                              "latency_ms": resp_timer.ms})
                audit.log_action("response", "generate_playbook",
                                 {"actions": len(report.recommended_actions)})

            # ── 6. OUTPUT GUARDRAILS ──
            valid, issues = self.output_guard.check(report, alert)
            trace.append({"step": "output_guardrails", "valid": valid, "issues": issues})
            if not valid:
                report.requires_human_review = True
                report.guardrail_blocks += 1
                audit.log_action("supervisor", "output_guardrail_fail", {"issues": issues})

        # Finalize
        report.trace = trace
        report.total_llm_calls = budget.calls
        report.total_tokens_used = budget.tokens
        report.total_latency_ms = total_timer.ms

        structured_log("INFO", "investigation_complete", agent_id="supervisor",
                       decision_source=report.decision_source.value,
                       tokens_used=report.total_tokens_used,
                       latency_ms=report.total_latency_ms,
                       extra={"severity": report.severity.value,
                              "confidence": report.confidence,
                              "actions": len(report.recommended_actions)})
        return report
