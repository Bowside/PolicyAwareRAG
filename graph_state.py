from typing import List, Dict, Any
from enum import Enum

class EnforcementDecision(Enum):
    """Possible enforcement outcomes produced by the agent graph."""
    ALLOW = "Allow"
    PARTIAL_REDACTION = "Partial_Redaction"
    DENY = "Deny"

class MultiAgentGraph:
    def __init__(self, agents: List):
        """Create an evaluation graph from a set of agent callables.

        Args:
            agents: Ordered list of agent functions that emit enforcement signals.
        """
        self.agents = agents

    def evaluate(self, chunks: List[Dict], policy_eval: Dict) -> Dict:
        """Aggregate agent signals into a single enforcement decision.

        Args:
            chunks: Retrieved content chunks under evaluation.
            policy_eval: Policy evaluation metadata passed to each agent.

        Returns:
            A dictionary containing the final decision and agent reasoning trail.
        """
        signals = []
        for agent in self.agents:
            try:
                sig = agent(chunks, policy_eval)
                signals.append(sig)
            except Exception as e:
                signals.append({"agent_error": str(e)})

        deny_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.DENY)
        redact_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.PARTIAL_REDACTION)
        allow_votes = sum(1 for s in signals if s.get("decision") == EnforcementDecision.ALLOW)

        if deny_votes > 0:
            final = EnforcementDecision.DENY
        elif redact_votes >= allow_votes:
            final = EnforcementDecision.PARTIAL_REDACTION
        else:
            final = EnforcementDecision.ALLOW

        reasoning = {
            "signals": signals,
            "tallies": {"deny": deny_votes, "redact": redact_votes, "allow": allow_votes}
        }
        return {"decision": final.value, "reasoning": reasoning}

def restrictive_agent(chunks, policy_eval):
    """Deny requests when any retrieved chunk is explicitly disallowed.

    Args:
        chunks: Retrieved content chunks under evaluation.
        policy_eval: Policy evaluation metadata, accepted for interface symmetry.

    Returns:
        An enforcement signal dictionary for the restrictive agent.
    """
    for c in chunks:
        if c.get("securityMetadata", {}).get("disallow", False):
            return {"agent": "restrictive_agent", "decision": EnforcementDecision.DENY, "note": "explicit disallow tag"}
    return {"agent": "restrictive_agent", "decision": EnforcementDecision.ALLOW}

def permissive_agent(chunks, policy_eval):
    """Allow satisfied policies or fall back to partial redaction.

    Args:
        chunks: Retrieved content chunks under evaluation.
        policy_eval: Policy evaluation metadata containing the satisfaction flag.

    Returns:
        An enforcement signal dictionary for the permissive agent.
    """
    if policy_eval.get("satisfied"):
        return {"agent": "permissive_agent", "decision": EnforcementDecision.ALLOW}
    return {"agent": "permissive_agent", "decision": EnforcementDecision.PARTIAL_REDACTION, "note": "policy not fully satisfied"}
