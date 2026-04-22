"""Agent permission policies — Principle of Least Privilege."""
from ..models import ActionRisk

POLICIES = {
    "triage": {
        "allowed": ["classify_alert", "query_knowledge_base"],
        "denied": ["isolate_endpoint", "block_ip", "disable_account"],
        "can_modify": False,
        "max_llm_calls": 3,
        "approval_required": [],
    },
    "enrichment": {
        "allowed": ["query_virustotal", "query_abuseipdb", "query_siem", "query_assets"],
        "denied": ["modify_systems", "write_to_siem"],
        "can_modify": False,
        "max_llm_calls": 2,
        "approval_required": [],
    },
    "response": {
        "allowed": ["generate_playbook", "isolate_endpoint", "block_ip",
                     "disable_account", "force_password_reset", "create_ticket"],
        "denied": ["delete_data", "wipe_endpoint"],
        "can_modify": True,
        "max_llm_calls": 3,
        "approval_required": ["isolate_endpoint", "block_ip", "disable_account", "force_password_reset"],
    },
}


def check_permission(agent_id: str, action: str) -> dict:
    policy = POLICIES.get(agent_id)
    if not policy:
        return {"allowed": False, "requires_approval": False, "reason": f"Unknown agent: {agent_id}"}
    if action in policy["denied"]:
        return {"allowed": False, "requires_approval": False, "reason": f"Denied: {action}"}
    if action not in policy["allowed"]:
        return {"allowed": False, "requires_approval": False, "reason": f"Not in allowed list: {action}"}
    needs = action in policy["approval_required"]
    return {"allowed": True, "requires_approval": needs, "reason": "OK" if not needs else "Needs HITL"}
