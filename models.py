from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class Principal(BaseModel):
    userId: str
    role: str
    declaredIntent: str

class PolicyEvaluation(BaseModel):
    matchedPolicyUid: Optional[str]
    ruleType: Optional[str]
    constraintSatisfaction: Dict[str, bool]
    reasoningTrail: List[str]

class EnforcementAction(BaseModel):
    actionType: str  # Allow | Partial_Redaction | Deny
    filteredNodesCount: int
    complianceGuardStatus: str  # Pass | Fail | Flagged

class GatewayAuditLogSchema(BaseModel):
    transactionId: str
    timestamp: datetime
    principal: Principal
    policyEvaluation: PolicyEvaluation
    enforcementAction: EnforcementAction
    extra: Optional[Dict[str, Any]] = None

class ODRLConstraint(BaseModel):
    purpose: Optional[List[str]] = None

class ODRLRule(BaseModel):
    uid: Optional[str]
    action: List[str]
    assigner: Optional[str]
    assignee: Optional[str]
    constraint: Optional[ODRLConstraint]

class ODRLPolicy(BaseModel):
    context: Optional[Any] = Field(..., alias='@context')
    type: Optional[str]
    uid: Optional[str]
    profile: Optional[str]
    rules: List[ODRLRule]
