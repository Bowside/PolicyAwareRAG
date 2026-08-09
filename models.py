from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime

class Principal(BaseModel):
    """Principal identity and intent supplied to the gateway."""

    userId: str
    role: str
    declaredIntent: str

class PolicyEvaluation(BaseModel):
    """Structured policy evaluation details captured in the audit log."""

    matchedPolicyUid: Optional[str] = None
    ruleType: Optional[str] = None
    constraintSatisfaction: Dict[str, bool] = {}
    reasoningTrail: List[str] = []

class EnforcementAction(BaseModel):
    """Final enforcement decision recorded for a request."""

    actionType: str  # Allow | Partial_Redaction | Deny
    filteredNodesCount: int
    complianceGuardStatus: str  # Pass | Fail | Flagged

class GatewayAuditLogSchema(BaseModel):
    """Audit log schema for a policy-aware RAG request."""

    transactionId: str
    timestamp: datetime
    startTime: datetime
    endTime: datetime
    durationSeconds: float
    principal: Principal
    policyEvaluation: PolicyEvaluation
    enforcementAction: EnforcementAction
    extra: Optional[Dict[str, Any]] = None

class ODRLConstraint(BaseModel):
    """Normalized ODRL constraint used by the validator."""

    leftOperand: Optional[str] = None
    operator: Optional[str] = None
    rightOperand: Optional[Any] = None
    purpose: Optional[List[str]] = None

class ODRLRule(BaseModel):
    """Normalized ODRL permission, prohibition, or duty rule."""

    uid: Optional[str] = None
    action: List[str]
    assigner: Optional[str] = None
    assignee: Optional[str] = None
    target: Optional[str] = None
    constraint: Optional[Any] = None

class ODRLPolicy(BaseModel):
    """Normalized ODRL 2.2 JSON-LD policy document."""

    model_config = ConfigDict(validate_by_name=True)

    context: Optional[Any] = Field(None, alias='@context')
    type: Optional[str] = Field(None, alias='@type')
    uid: Optional[str] = None
    profile: Optional[str] = None
    permission: List[ODRLRule] = Field(default_factory=list)
    prohibition: List[ODRLRule] = Field(default_factory=list)
    duty: List[ODRLRule] = Field(default_factory=list)
