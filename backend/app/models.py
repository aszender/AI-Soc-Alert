"""
Domain models for the AI SOC Alert platform.

All models use Pydantic for runtime validation — if a field is wrong,
we get a clear error instead of a silent bug in production.
"""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ── Enums ──

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    FALSE_POSITIVE = "false_positive"


class TrustLevel(str, Enum):
    SYSTEM = "system"
    VERIFIED = "verified"
    ENRICHED = "enriched"
    UNTRUSTED = "untrusted"


class ActionRisk(str, Enum):
    READ_ONLY = "read_only"
    LOW_RISK = "low_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"


class DecisionSource(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"


# ── Input Models ──

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_tool: str = ""
    alert_type: str = ""
    description: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    raw_event: dict = Field(default_factory=dict)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED


# ── Output Models ──

class EnrichmentResult(BaseModel):
    indicator: str = ""
    indicator_type: str = ""
    source: str = ""
    is_malicious: Optional[bool] = None
    confidence: float = 0.0
    details: str = ""


class RecommendedAction(BaseModel):
    action: str
    target: str
    reason: str
    risk_level: ActionRisk = ActionRisk.READ_ONLY
    requires_approval: bool = False
    approved: bool = False
    approved_by: Optional[str] = None


class InvestigationReport(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    alert_id: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    mitre_technique: str = ""
    mitre_name: str = ""
    attack_narrative: str = ""
    decision_source: DecisionSource = DecisionSource.LLM
    affected_assets: list[str] = Field(default_factory=list)
    enrichment_results: list[EnrichmentResult] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    requires_human_review: bool = True
    trace: list[dict] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Observability
    total_llm_calls: int = 0
    total_tokens_used: int = 0
    total_latency_ms: float = 0.0
    guardrail_blocks: int = 0


# ── Approval ──

class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex[:8])
    investigation_id: str
    action: str
    target: str
    risk_level: ActionRisk
    reason: str
    status: str = "pending"  # pending | approved | rejected
    requested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None


# ── API Request/Response ──

class InvestigateRequest(BaseModel):
    source_tool: str
    alert_type: str = ""
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    raw_event: dict = Field(default_factory=dict)


class HealthResponse(BaseModel):
    status: str = "healthy"
    mode: str = "demo"
    version: str = "1.0.0"
    integrations: dict = Field(default_factory=dict)
