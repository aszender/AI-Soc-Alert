"""Human-in-the-Loop approval gates for high-risk actions."""
from datetime import datetime, timezone
from ..models import RecommendedAction, ActionRisk, ApprovalRequest

_pending: list[ApprovalRequest] = []
_history: list[ApprovalRequest] = []

APPROVAL_MAP = {
    ActionRisk.READ_ONLY: "auto",
    ActionRisk.LOW_RISK: "auto",
    ActionRisk.HIGH_RISK: "analyst",
    ActionRisk.CRITICAL: "dual",
}


def request_approval(action: RecommendedAction, investigation_id: str) -> ApprovalRequest:
    mode = APPROVAL_MAP[action.risk_level]
    req = ApprovalRequest(
        investigation_id=investigation_id,
        action=action.action,
        target=action.target,
        risk_level=action.risk_level,
        reason=action.reason,
    )
    if mode == "auto":
        req.status = "approved"
        req.decided_by = "system"
        req.decided_at = datetime.now(timezone.utc).isoformat()
        _history.append(req)
    else:
        _pending.append(req)
    return req


def approve(request_id: str, approver: str) -> ApprovalRequest | None:
    for req in _pending:
        if req.id == request_id:
            req.status = "approved"
            req.decided_by = approver
            req.decided_at = datetime.now(timezone.utc).isoformat()
            _pending.remove(req)
            _history.append(req)
            return req
    return None


def reject(request_id: str, rejector: str) -> ApprovalRequest | None:
    for req in _pending:
        if req.id == request_id:
            req.status = "rejected"
            req.decided_by = rejector
            req.decided_at = datetime.now(timezone.utc).isoformat()
            _pending.remove(req)
            _history.append(req)
            return req
    return None


def get_pending() -> list[ApprovalRequest]:
    return list(_pending)


def get_history() -> list[ApprovalRequest]:
    return list(_history)
