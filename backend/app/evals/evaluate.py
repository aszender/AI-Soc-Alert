"""
Evaluation suite — Measures AI SOC Alert quality.

Metrics:
- severity_accuracy: Did we classify correctly?
- decision_source_accuracy: Did we use rules vs LLM correctly?
- schema_valid_rate: Did every report have valid fields?
- prompt_injection_block_rate: Did guardrails catch injections?
- hallucinated_ioc_rate: Did output guardrails catch hallucinations?
- human_review_rate: What % of alerts need human review?
- deterministic_ratio: What % handled by rules (no LLM cost)?

Run: python -m backend.app.evals.evaluate
"""
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from backend.app.models import Alert
from backend.app.core.llm_client import LLMClient
from backend.app.agents.supervisor import SupervisorAgent


def load_golden_alerts() -> list[dict]:
    path = os.path.join(os.path.dirname(__file__), "golden_alerts.json")
    with open(path) as f:
        return json.load(f)


def run_evaluation():
    alerts = load_golden_alerts()
    llm = LLMClient()
    supervisor = SupervisorAgent(llm)

    results = []
    for alert_data in alerts:
        alert = Alert(
            source_tool=alert_data.get("source_tool", ""),
            alert_type=alert_data.get("alert_type", ""),
            description=alert_data.get("description", ""),
            source_ip=alert_data.get("source_ip"),
            destination_ip=alert_data.get("destination_ip"),
            username=alert_data.get("username"),
            hostname=alert_data.get("hostname"),
            process_name=alert_data.get("process_name"),
            raw_event=alert_data.get("raw_event", {}),
        )
        report = supervisor.investigate(alert)
        results.append({
            "id": alert_data["id"],
            "expected_severity": alert_data["expected_severity"],
            "actual_severity": report.severity.value,
            "severity_match": report.severity.value == alert_data["expected_severity"],
            "expected_source": alert_data["expected_decision_source"],
            "actual_source": report.decision_source.value,
            "source_match": report.decision_source.value == alert_data["expected_decision_source"],
            "schema_valid": _validate_schema(report),
            "human_review": report.requires_human_review,
            "guardrail_blocks": report.guardrail_blocks,
            "llm_calls": report.total_llm_calls,
            "tokens_used": report.total_tokens_used,
            "latency_ms": report.total_latency_ms,
            "notes": alert_data.get("notes", ""),
        })

    _print_results(results)
    return results


def _validate_schema(report) -> bool:
    """Check that the report has all required fields with valid values."""
    try:
        assert report.severity is not None
        assert 0.0 <= report.confidence <= 1.0
        assert report.alert_id != ""
        assert report.decision_source is not None
        return True
    except (AssertionError, AttributeError):
        return False


def _print_results(results: list[dict]):
    total = len(results)
    severity_matches = sum(1 for r in results if r["severity_match"])
    source_matches = sum(1 for r in results if r["source_match"])
    schema_valid = sum(1 for r in results if r["schema_valid"])
    human_reviews = sum(1 for r in results if r["human_review"])
    guardrail_blocks = sum(r["guardrail_blocks"] for r in results)
    deterministic = sum(1 for r in results if r["actual_source"] == "deterministic")
    llm_used = sum(1 for r in results if r["actual_source"] == "llm")
    total_tokens = sum(r["tokens_used"] for r in results)
    total_latency = sum(r["latency_ms"] for r in results)

    print("\n" + "=" * 65)
    print("  AI SOC ALERT INVESTIGATOR — EVALUATION RESULTS")
    print("=" * 65)

    print(f"\n  Alerts evaluated:           {total}")
    print(f"  Severity accuracy:          {severity_matches}/{total} ({severity_matches/total*100:.0f}%)")
    print(f"  Decision source accuracy:   {source_matches}/{total} ({source_matches/total*100:.0f}%)")
    print(f"  Schema valid rate:          {schema_valid}/{total} ({schema_valid/total*100:.0f}%)")
    print(f"  Guardrail blocks:           {guardrail_blocks}")
    print(f"  Human review rate:          {human_reviews}/{total} ({human_reviews/total*100:.0f}%)")
    print(f"  Deterministic ratio:        {deterministic}/{total} ({deterministic/total*100:.0f}%)")
    print(f"  LLM ratio:                  {llm_used}/{total} ({llm_used/total*100:.0f}%)")
    print(f"  Total tokens consumed:      {total_tokens}")
    print(f"  Total latency:              {total_latency:.0f}ms")

    print(f"\n  {'ID':<12} {'Expected':<16} {'Actual':<16} {'Source':<15} {'Match'}")
    print(f"  {'─'*12} {'─'*16} {'─'*16} {'─'*15} {'─'*5}")
    for r in results:
        match = "PASS" if r["severity_match"] else "FAIL"
        print(f"  {r['id']:<12} {r['expected_severity']:<16} {r['actual_severity']:<16} "
              f"{r['actual_source']:<15} {match}")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    run_evaluation()
