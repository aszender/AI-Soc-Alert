"""
API routes for the AI SOC Alert Investigator.

POST /alerts/investigate   — Submit an alert for investigation
GET  /investigations/{id}  — Get investigation results
GET  /approvals/pending    — View pending HITL approvals
POST /approvals/{id}/approve — Approve a pending action
POST /approvals/{id}/reject  — Reject a pending action
GET  /health               — Integration and system health
"""
from fastapi import APIRouter, HTTPException
from ..models import InvestigateRequest, Alert, HealthResponse
from ..core.llm_client import LLMClient
from ..core.config import settings
from ..agents.supervisor import SupervisorAgent
from ..governance import hitl

router = APIRouter()

# In-memory store (in production: database)
_investigations: dict = {}
_llm = LLMClient()
_supervisor = SupervisorAgent(_llm)


@router.post("/alerts/investigate")
def investigate_alert(req: InvestigateRequest):
    alert = Alert(
        source_tool=req.source_tool,
        alert_type=req.alert_type,
        description=req.description,
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        username=req.username,
        hostname=req.hostname,
        process_name=req.process_name,
        raw_event=req.raw_event,
    )
    report = _supervisor.investigate(alert)
    _investigations[report.id] = report
    return report.model_dump()


@router.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    report = _investigations.get(investigation_id)
    if not report:
        raise HTTPException(404, "Investigation not found")
    return report.model_dump()


@router.get("/approvals/pending")
def pending_approvals():
    return [a.model_dump() for a in hitl.get_pending()]


@router.post("/approvals/{request_id}/approve")
def approve_action(request_id: str, approver: str = "analyst"):
    result = hitl.approve(request_id, approver)
    if not result:
        raise HTTPException(404, "Approval request not found")
    return result.model_dump()


@router.post("/approvals/{request_id}/reject")
def reject_action(request_id: str, rejector: str = "analyst"):
    result = hitl.reject(request_id, rejector)
    if not result:
        raise HTTPException(404, "Approval request not found")
    return result.model_dump()


@router.get("/health", response_model=HealthResponse)
def health_check():
    return HealthResponse(
        status="healthy",
        mode="demo" if settings.is_demo_mode else "production",
        integrations={"llm": _llm.get_stats()},
    )
