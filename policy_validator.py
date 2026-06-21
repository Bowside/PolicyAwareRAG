from models import ODRLPolicy
from pydantic import ValidationError
from typing import Tuple

class PolicyPurposeValidator:
    def __init__(self, odrl_jsonld: dict):
        """Parse and store an ODRL policy document.

        Args:
            odrl_jsonld: JSON-LD policy payload conforming to the local ODRL schema.

        Raises:
            ValueError: If the policy cannot be validated against the ODRL model.
        """
        try:
            self.policy = ODRLPolicy(**odrl_jsonld)
        except ValidationError as e:
            raise ValueError(f"Invalid ODRL policy: {e}")

    def evaluate(self, principal_role: str, declared_intent: str, action: str) -> Tuple[bool, dict]:
        """Evaluate whether the declared intent satisfies the policy rules.

        Args:
            principal_role: Role declared by the principal.
            declared_intent: Intent declared by the principal.
            action: Requested action to evaluate against the policy rules.

        Returns:
            A tuple containing the allow decision and a detailed evaluation record.
        """
        matched_rules = []
        reasoning = []
        satisfied = False

        for rule in self.policy.rules:
            actions = [a.lower() for a in rule.action]
            if action.lower() in actions:
                matched_rules.append(rule)
                reasoning.append(f"matched rule {rule.uid or 'unknown'} for action {action}")
                if rule.constraint and rule.constraint.purpose:
                    allowed_purposes = [p.lower() for p in rule.constraint.purpose]
                    if declared_intent.lower() in allowed_purposes:
                        satisfied = True
                        reasoning.append("declared intent satisfied purpose constraint")
                    else:
                        reasoning.append("declared intent NOT in permitted purposes")
                else:
                    satisfied = True
                    reasoning.append("no purpose constraint -> permissive")
        evaluation = {
            "matchedRules": [r.uid for r in matched_rules],
            "reasoning": reasoning,
            "action": action,
            "declared_intent": declared_intent,
            "principal_role": principal_role,
            "satisfied": satisfied
        }
        return satisfied, evaluation
