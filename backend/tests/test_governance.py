"""Tests for governance controls and rules engine."""
import pytest
from backend.app.governance.permissions import check_permission
from backend.app.governance.hitl import request_approval, approve, reject, get_pending, _pending, _history
from backend.app.governance.budget import BudgetGovernor
from backend.app.core.rules_engine import RulesEngine
from backend.app.models import RecommendedAction, ActionRisk, Alert


class TestPermissions:
    def test_triage_can_classify(self):
        r = check_permission("triage", "classify_alert")
        assert r["allowed"] is True
        assert r["requires_approval"] is False

    def test_triage_cannot_isolate(self):
        r = check_permission("triage", "isolate_endpoint")
        assert r["allowed"] is False

    def test_response_can_isolate_with_approval(self):
        r = check_permission("response", "isolate_endpoint")
        assert r["allowed"] is True
        assert r["requires_approval"] is True

    def test_response_cannot_wipe(self):
        r = check_permission("response", "wipe_endpoint")
        assert r["allowed"] is False

    def test_unknown_agent_denied(self):
        r = check_permission("rogue_agent", "anything")
        assert r["allowed"] is False


class TestHITL:
    def setup_method(self):
        _pending.clear()
        _history.clear()

    def test_read_only_auto_approved(self):
        action = RecommendedAction(action="query", target="SIEM",
                                    reason="test", risk_level=ActionRisk.READ_ONLY)
        req = request_approval(action, "inv-001")
        assert req.status == "approved"

    def test_critical_needs_approval(self):
        action = RecommendedAction(action="isolate", target="HOST-1",
                                    reason="test", risk_level=ActionRisk.CRITICAL)
        req = request_approval(action, "inv-001")
        assert req.status == "pending"
        assert len(get_pending()) == 1

    def test_approve_workflow(self):
        action = RecommendedAction(action="block_ip", target="1.2.3.4",
                                    reason="test", risk_level=ActionRisk.HIGH_RISK)
        req = request_approval(action, "inv-001")
        result = approve(req.id, "analyst_jane")
        assert result is not None
        assert result.status == "approved"
        assert len(get_pending()) == 0

    def test_reject_workflow(self):
        action = RecommendedAction(action="block_ip", target="1.2.3.4",
                                    reason="test", risk_level=ActionRisk.HIGH_RISK)
        req = request_approval(action, "inv-001")
        result = reject(req.id, "analyst_jane")
        assert result.status == "rejected"


class TestBudget:
    def test_within_budget(self):
        b = BudgetGovernor()
        assert b.can_call() is True

    def test_exceeds_calls(self):
        b = BudgetGovernor()
        for _ in range(20):
            b.record(100)
        assert b.can_call() is False

    def test_stats(self):
        b = BudgetGovernor()
        b.record(500)
        s = b.stats()
        assert s["llm_calls"] == 1
        assert s["tokens_used"] == 500


class TestRulesEngine:
    def setup_method(self):
        self.engine = RulesEngine()

    def test_mimikatz_deterministic_critical(self):
        alert = Alert(description="Mimikatz detected", process_name="mimikatz.exe")
        result = self.engine.evaluate(alert)
        assert result is not None
        assert result["severity"] == "critical"
        assert result["decision_source"] == "deterministic"

    def test_cobalt_strike_deterministic(self):
        alert = Alert(description="Cobalt Strike beacon", process_name="beacon.exe")
        result = self.engine.evaluate(alert)
        assert result is not None
        assert result["severity"] == "critical"

    def test_nessus_scan_false_positive(self):
        alert = Alert(source_tool="Nessus", alert_type="ScheduledScan",
                      description="Completed scan")
        result = self.engine.evaluate(alert)
        assert result is not None
        assert result["severity"] == "false_positive"

    def test_cert_expiry_low(self):
        alert = Alert(description="SSL certificate for api.corp.com expires in 5 days")
        result = self.engine.evaluate(alert)
        assert result is not None
        assert result["severity"] == "low"

    def test_unknown_alert_returns_none(self):
        alert = Alert(description="Something unusual happened")
        result = self.engine.evaluate(alert)
        assert result is None  # Needs LLM
