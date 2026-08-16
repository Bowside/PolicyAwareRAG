"""Orchestration graph state management and enforcement decision logic.

Defines the multi-agent graph pattern for policy enforcement:
- EnforcementDecision enum for standardized decision values
- MultiAgentGraph for aggregating agent signals into final decisions
- Enforcement agents (restrictive_agent, permissive_agent) implementing decision logic

Uses voting/consensus pattern where agents signal Allow/Deny/Partial_Redaction
and the graph applies decision rules (deny votes veto, redaction wins ties).
"""
from typing import List, Dict, Any
from enum import Enum


class EnforcementDecision(Enum):
    """Possible enforcement outcomes produced by the agent graph.
    
    Standardized enforcement actions that agents can vote for and the graph
    aggregates into a final decision.
    
    Attributes:
        ALLOW: Permit full response to principal without redaction.
        PARTIAL_REDACTION: Allow response with PII/sensitive content redacted.
        DENY: Reject request entirely, no content returned.
    """
    ALLOW = "Allow"
    PARTIAL_REDACTION = "Partial_Redaction"
    DENY = "Deny"

class MultiAgentGraph:
    """Multi-agent graph for aggregating enforcement signals into final decisions.
    
    Implements a voting-based consensus pattern where independent agents evaluate
    policy compliance and vote for Allow/Deny/Partial_Redaction. The graph then
    applies aggregation rules (deny votes veto, redaction wins ties) to reach a
    final decision.
    
    Attributes:
        agents: Ordered list of agent callables, each taking (chunks, policy_eval)
                and returning a signal dict with 'decision' field.
    """
    def __init__(self, agents: List):
        """Create an evaluation graph from a set of agent callables.

        Args:
            agents: Ordered list of agent functions that emit enforcement signals.
                   Each agent should accept (chunks, policy_eval) and return dict
                   with 'decision' field (EnforcementDecision enum or string value).
        """
        self.agents = agents

    def evaluate(self, chunks: List[Dict], policy_eval: Dict) -> Dict:
        """Aggregate agent signals into a single enforcement decision.
        
        Executes all agents, collects their enforcement signals, tallies votes,
        and applies decision rules:
        - Any DENY vote → final DENY (fail-secure)
        - REDACTION votes >= ALLOW votes → final REDACTION
        - Otherwise → final ALLOW
        
        Agent errors are captured but don't block evaluation (graceful degradation).

        Args:
            chunks: Retrieved content chunks under evaluation, passed to each agent
                   for content-based decision logic.
            policy_eval: Policy evaluation metadata (e.g., constraint satisfaction)
                        passed to each agent for policy-based decision logic.

        Returns:
            dict: Decision dictionary with keys:
                - decision: Final enforcement action ('Allow', 'Deny', 'Partial_Redaction')
                - reasoning: Dict with 'signals' (agent outputs) and 'tallies' (vote counts)
        """
        signals = []
        # Collect enforcement signals from all agents
        for agent in self.agents:
            try:
                sig = agent(chunks, policy_eval)
                # Normalize enum to string value for serialization
                if isinstance(sig, dict) and isinstance(sig.get("decision"), EnforcementDecision):
                    sig = dict(sig)
                    sig["decision"] = sig["decision"].value
                signals.append(sig)
            except Exception as e:
                # Capture agent execution errors without failing the evaluation
                signals.append({"agent_error": str(e)})

        # Tally votes from all agents
        deny_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.DENY.value)
        redact_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.PARTIAL_REDACTION.value)
        allow_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.ALLOW.value)

        # Apply decision rules: deny veto, redaction wins ties, allow default
        if deny_votes > 0:
            final = EnforcementDecision.DENY.value
        elif redact_votes >= allow_votes:
            final = EnforcementDecision.PARTIAL_REDACTION.value
        else:
            final = EnforcementDecision.ALLOW.value

        reasoning = {
            "signals": signals,
            "tallies": {"deny": deny_votes, "redact": redact_votes, "allow": allow_votes}
        }
        return {"decision": final, "reasoning": reasoning}

def restrictive_agent(chunks, policy_eval):
    """Deny requests when any retrieved chunk is explicitly disallowed.
    
    Implements a conservative content-based agent that checks metadata flags
    on retrieved chunks. Any chunk tagged with disallow=true causes immediate
    denial (fail-secure). Used as a veto mechanism for obviously problematic content.

    Args:
        chunks: Retrieved content chunks under evaluation. Each chunk should have
               optional 'securityMetadata' dict with 'disallow' boolean field.
        policy_eval: Policy evaluation metadata (unused by this agent, accepted for interface symmetry).

    Returns:
        dict: Enforcement signal with keys:
            - agent: 'restrictive_agent' (for identification)
            - decision: 'Deny' if any disallow tag, else 'Allow'
            - note: Explanation string if decision is 'Deny'
    """
    # Check each chunk for explicit disallow security tag
    for c in chunks:
        if c.get("securityMetadata", {}).get("disallow", False):
            return {"agent": "restrictive_agent", "decision": EnforcementDecision.DENY.value, "note": "explicit disallow tag"}
    return {"agent": "restrictive_agent", "decision": EnforcementDecision.ALLOW.value}

def permissive_agent(chunks, policy_eval):
    """Allow satisfied policies or fall back to partial redaction.
    
    Implements a policy-based agent that checks if ODRL policy constraints
    are fully satisfied. If satisfied, votes to allow; otherwise votes for
    partial redaction. The policy_eval metadata from the policy validator
    determines the decision.

    Args:
        chunks: Retrieved content chunks under evaluation (unused by this agent,
               accepted for interface symmetry).
        policy_eval: Policy evaluation metadata containing:
                    - satisfied (bool): Whether policy constraints are satisfied
                    Other fields are ignored by this agent.

    Returns:
        dict: Enforcement signal with keys:
            - agent: 'permissive_agent' (for identification)
            - decision: 'Allow' if policy satisfied, else 'Partial_Redaction'
            - note: Explanation string if decision is 'Partial_Redaction'
    """
    # Check if policy evaluation passed all constraints
    if policy_eval.get("satisfied"):
        return {"agent": "permissive_agent", "decision": EnforcementDecision.ALLOW.value}
    return {"agent": "permissive_agent", "decision": EnforcementDecision.PARTIAL_REDACTION.value, "note": "policy not fully satisfied"}
