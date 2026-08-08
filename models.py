from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime

class Principal(BaseModel):
    userId: str
    role: str
    declaredIntent: str

class PolicyEvaluation(BaseModel):
    matchedPolicyUid: Optional[str] = None
    ruleType: Optional[str] = None
    constraintSatisfaction: Dict[str, bool] = {}
    reasoningTrail: List[str] = []

class EnforcementAction(BaseModel):
    actionType: str  # Allow | Partial_Redaction | Deny
    filteredNodesCount: int
    complianceGuardStatus: str  # Pass | Fail | Flagged

class GatewayAuditLogSchema(BaseModel):
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
    leftOperand: Optional[str] = None
    operator: Optional[str] = None
    rightOperand: Optional[Any] = None
    purpose: Optional[List[str]] = None

class ODRLRule(BaseModel):
    uid: Optional[str] = None
    action: List[str]
    assigner: Optional[str] = None
    assignee: Optional[str] = None
    target: Optional[str] = None
    constraint: Optional[Any] = None

class ODRLPolicy(BaseModel):
    model_config = ConfigDict(validate_by_name=True)

    context: Optional[Any] = Field(None, alias='@context')
    type: Optional[str] = Field(None, alias='@type')
    uid: Optional[str] = None
    profile: Optional[str] = None
    permission: List[ODRLRule] = Field(default_factory=list)
    prohibition: List[ODRLRule] = Field(default_factory=list)
    duty: List[ODRLRule] = Field(default_factory=list)
