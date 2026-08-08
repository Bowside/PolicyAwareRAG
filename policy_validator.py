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
        # Preprocess incoming policy to be tolerant of missing optional fields
        prepped = dict(odrl_jsonld) if odrl_jsonld is not None else {}
        if "rules" in prepped:
            raise ValueError("Invalid ODRL policy: legacy 'rules' shape is not supported; use 'permission' and 'prohibition'.")
        if "prohibition" not in prepped:
            prepped["prohibition"] = []
        if "duty" not in prepped:
            prepped["duty"] = []

        try:
            self.policy = ODRLPolicy(**prepped)
        except ValidationError as e:
            raise ValueError(f"Invalid ODRL policy: {e}")

    def _rule_groups(self):
        permissions = self.policy.permission or []
        prohibitions = self.policy.prohibition or []
        return permissions, prohibitions

    @staticmethod
    def _rule_constraints(rule):
        constraints = rule.constraint
        if constraints is None:
            return []
        if isinstance(constraints, list):
            return constraints
        return [constraints]

    @staticmethod
    def _constraint_purposes(constraint):
        if not isinstance(constraint, dict):
            return []

        purposes = []
        if constraint.get("purpose"):
            purpose_value = constraint["purpose"]
            if isinstance(purpose_value, list):
                purposes.extend(purpose_value)
            else:
                purposes.append(purpose_value)
        elif constraint.get("leftOperand") == "purpose":
            right_operand = constraint.get("rightOperand")
            if isinstance(right_operand, list):
                purposes.extend(right_operand)
            elif right_operand is not None:
                purposes.append(str(right_operand))
        return purposes

    def _constraint_allows(self, rule, declared_intent: str) -> Tuple[bool, str]:
        constraints = self._rule_constraints(rule)
        if not constraints:
            return True, "no purpose constraint -> permissive"

        allowed_purposes = []
        for constraint in constraints:
            allowed_purposes.extend(self._constraint_purposes(constraint))

        if not allowed_purposes:
            return True, "no purpose constraint -> permissive"

        if declared_intent.lower() in [purpose.lower() for purpose in allowed_purposes]:
            return True, "declared intent satisfied purpose constraint"

        return False, "declared intent NOT in permitted purposes"

    @staticmethod
    def _canonical_role(value: str | None) -> str:
        if not value:
            return ""

        normalized = value.strip().rstrip("/ ")
        for separator in ("#", "/", ":"):
            if separator in normalized:
                normalized = normalized.rsplit(separator, 1)[-1]

        normalized = normalized.lower()
        aliases = {
            "privacy-analyst": "privacy-compliance-analyst",
            "support-limited": "customer-support-specialist",
            "customer-support": "customer-support-specialist",
            "customer-support-specialist": "customer-support-specialist",
            "business-observer": "business-observer",
            "pii-data-governance-admin": "pii-data-governance-admin",
            "privacy-compliance-analyst": "privacy-compliance-analyst",
        }
        return aliases.get(normalized, normalized)

    def _role_allows(self, rule, principal_role: str) -> Tuple[bool, str]:
        if not getattr(rule, "assignee", None):
            return True, "no assignee constraint -> permissive"

        principal_token = self._canonical_role(principal_role)
        assignee_token = self._canonical_role(rule.assignee)

        if principal_token and principal_token == assignee_token:
            return True, "principal role matched assignee"

        return False, "principal role did not match assignee"

    def evaluate(self, principal_role: str, declared_intent: str, action: str) -> Tuple[bool, dict]:
        """Evaluate whether the declared intent satisfies the policy rules.

        Args:
            principal_role: Role declared by the principal.
            declared_intent: Intent declared by the principal.
            action: Requested action to evaluate against the policy rules.

        Returns:
            A tuple containing the allow decision and a detailed evaluation record.
        """
        permissions, prohibitions = self._rule_groups()
        matched_rules = []
        reasoning = []
        satisfied = False

        for rule in prohibitions:
            actions = [a.lower() for a in rule.action]
            if action.lower() not in actions:
                continue

            matched_rules.append(rule)
            reasoning.append(f"matched prohibition {rule.uid or 'unknown'} for action {action}")
            role_allowed, role_reason = self._role_allows(rule, principal_role)
            reasoning.append(role_reason)
            if not role_allowed:
                continue
            allowed, constraint_reason = self._constraint_allows(rule, declared_intent)
            reasoning.append(constraint_reason)
            if allowed:
                reasoning.append("prohibition matched -> denied")
                evaluation = {
                    "matchedRules": [r.uid for r in matched_rules],
                    "reasoning": reasoning,
                    "action": action,
                    "declared_intent": declared_intent,
                    "principal_role": principal_role,
                    "satisfied": False,
                }
                return False, evaluation

        for rule in permissions:
            actions = [a.lower() for a in rule.action]
            if action.lower() not in actions:
                continue

            matched_rules.append(rule)
            reasoning.append(f"matched permission {rule.uid or 'unknown'} for action {action}")
            role_allowed, role_reason = self._role_allows(rule, principal_role)
            reasoning.append(role_reason)
            if not role_allowed:
                continue
            allowed, constraint_reason = self._constraint_allows(rule, declared_intent)
            reasoning.append(constraint_reason)
            if allowed:
                satisfied = True

        evaluation = {
            "matchedRules": [r.uid for r in matched_rules],
            "reasoning": reasoning,
            "action": action,
            "declared_intent": declared_intent,
            "principal_role": principal_role,
            "satisfied": satisfied
        }
        return satisfied, evaluation
