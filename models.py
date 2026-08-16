"""Data models for Policy-Aware RAG gateway.

Defines Pydantic models for:
- Request/response data (Principal, QueryRequest)
- Audit logging (GatewayAuditLogSchema, PolicyEvaluation, EnforcementAction)
- ODRL 2.2 policy representation (ODRLPolicy, ODRLRule, ODRLConstraint)
- Graph state management

All models use Pydantic for validation and JSON serialization.
"""
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional
from datetime import datetime


class Principal(BaseModel):
    """Principal identity and security context supplied to the gateway.
    
    Captures the caller's identity, role, and stated intent for policy evaluation.
    The role is matched against ODRL policy assignee fields, and declaredIntent
    is validated against policy constraints.
    
    Attributes:
        userId: Unique identifier for the principal (e.g., email, username).
        role: Role-based access control designation (e.g., 'privacy-analyst', 'admin').
        declaredIntent: Stated purpose for the request (e.g., 'privacy_review', 'business_analysis').
    """

    userId: str
    role: str
    declaredIntent: str

class PolicyEvaluation(BaseModel):
    """Structured policy evaluation details captured in the audit log.
    
    Records which policy rule matched, constraint satisfaction results, and
    the reasoning trail showing which rules/constraints were evaluated.
    
    Attributes:
        matchedPolicyUid: UID of the ODRL policy rule that matched (permission/prohibition).
        ruleType: Type of matched rule ('permission', 'prohibition', or 'duty').
        constraintSatisfaction: Dict mapping constraint expressions to bool (True=satisfied).
        reasoningTrail: List of human-readable strings explaining policy evaluation steps.
    """

    matchedPolicyUid: Optional[str] = None
    ruleType: Optional[str] = None
    constraintSatisfaction: Dict[str, bool] = {}
    reasoningTrail: List[str] = []

class EnforcementAction(BaseModel):
    """Final enforcement decision recorded for a request.
    
    Contains the enforcement action type (Allow/Deny/Partial_Redaction), count of
    filtered nodes, and compliance guard pass/fail/flagged status indicating whether
    the response passed PII redaction checks.
    
    Attributes:
        actionType: Enforcement action: 'Allow' (permit full response), 'Partial_Redaction' (redact PII),
                    or 'Deny' (reject request entirely).
        filteredNodesCount: Number of response nodes/chunks that were redacted or filtered.
        complianceGuardStatus: Result of PII compliance check: 'Pass' (safe), 'Fail' (PII detected),
                               or 'Flagged' (suspicious/review needed).
    """

class GatewayAuditLogSchema(BaseModel):
    """Audit log schema for a policy-aware RAG request.
    
    Comprehensive record of request processing including timing, principal context,
    policy evaluation outcome, and enforcement action. Stored in Cosmos DB for
    compliance auditing and forensic analysis.
    
    Attributes:
        transactionId: Unique identifier for this request (UUID).
        timestamp: ISO 8601 timestamp when audit event was created.
        startTime: When request processing began.
        endTime: When request processing completed.
        durationSeconds: Total processing time in seconds.
        principal: Principal identity and intent from request.
        policyEvaluation: Policy rule matching and constraint satisfaction details.
        enforcementAction: Final enforcement decision (Allow/Deny/Partial_Redaction).
        extra: Optional additional metadata for debugging or tracing.
    """

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
    """Normalized ODRL constraint used by the validator.
    
    Represents a constraint expression from an ODRL rule that must be satisfied
    for the rule to apply. Constraints limit rule applicability based on context,
    including time, purpose, location, user attributes, etc.
    
    Attributes:
        leftOperand: The constraint variable being tested (e.g., 'purpose', 'dateTime', 'user').
        operator: Comparison operator (e.g., 'isA', 'eq', 'lte', 'in', 'contains').
        rightOperand: The expected value or range for the constraint.
        purpose: List of allowable purposes if this is a purpose constraint.
    """

    leftOperand: Optional[str] = None
    operator: Optional[str] = None
    rightOperand: Optional[Any] = None
    purpose: Optional[List[str]] = None

class ODRLRule(BaseModel):
    """Normalized ODRL permission, prohibition, or duty rule.
    
    Represents a single rule from an ODRL policy that permits, prohibits, or
    prescribes obligations for resource access. Rules specify who (assignee),
    what action, on what target (resource), under what constraints.
    
    Attributes:
        uid: Unique identifier for this rule within the policy.
        action: List of permitted/prohibited actions (e.g., ['read', 'export'], ['delete']).
        assigner: Entity that grants permissions (policy creator/issuer).
        assignee: Entity to which the rule applies (matched against principal role).
        target: Resource identifier or pattern the rule applies to (optional wildcard).
        constraint: Constraint object or dict specifying conditions for rule applicability.
    """

    uid: Optional[str] = None
    action: List[str]
    assigner: Optional[str] = None
    assignee: Optional[str] = None
    target: Optional[str] = None
    constraint: Optional[Any] = None

class ODRLPolicy(BaseModel):
    """Normalized ODRL 2.2 JSON-LD policy document.
    
    Represents a complete ODRL policy with permissions, prohibitions, and duties.
    Supports JSON-LD context and type fields. Can be populated from parsed ODRL JSON
    files and provides structured access to policy rules for evaluation.
    
    Attributes:
        context: JSON-LD @context field for semantic namespace resolution.
        type: JSON-LD @type field (typically 'odrl:Policy').
        uid: Unique policy identifier (e.g., 'urn:policy:privacy-review').
        profile: ODRL profile designation (e.g., 'odrl:v2.2').
        permission: List of permission rules (actions that are allowed).
        prohibition: List of prohibition rules (actions that are forbidden).
        duty: List of duty rules (obligations on the assignee).
    """
    # Enable validation by both attribute name and alias (for @context, @type JSON-LD fields)
    model_config = ConfigDict(validate_by_name=True)

    context: Optional[Any] = Field(None, alias='@context')
    type: Optional[str] = Field(None, alias='@type')
    uid: Optional[str] = None
    profile: Optional[str] = None
    permission: List[ODRLRule] = Field(default_factory=list)
    prohibition: List[ODRLRule] = Field(default_factory=list)
    duty: List[ODRLRule] = Field(default_factory=list)
