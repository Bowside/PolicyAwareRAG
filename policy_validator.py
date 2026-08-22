"""Policy validation helpers for ODRL-based intent and role enforcement.

The validator inspects permission and prohibition rules in an ODRL policy,
normalizes IRI-style role values, and evaluates whether a principal's declared
intent and role satisfy the policy for a requested action. This module is used
by the orchestrator to decide whether data may be retrieved, denied, or partially
redacted before being returned to the user.
"""

from typing import Tuple

from pydantic import ValidationError

from models import ODRLPolicy


class PolicyPurposeValidator:
    """Validate role and purpose constraints for an ODRL policy.

    The validator supports the policy semantics used by this application:
    - role checks against rule assignee values
    - purpose checks against the principal's declared intent
    - permission and prohibition evaluation for a requested action
    - deriving Cosmos DB security filters from the first matching rule
    """

    def __init__(self, odrl_jsonld: dict):
        """Parse and store an ODRL policy document.

        Args:
            odrl_jsonld: JSON-LD policy payload conforming to the local ODRL schema.

        Raises:
            ValueError: If the policy cannot be validated against the ODRL model.
        """
        # Preprocess incoming policy to be tolerant of missing optional fields.
        prepped = dict(odrl_jsonld) if odrl_jsonld is not None else {}
        if "rules" in prepped:
            raise ValueError(
                "Invalid ODRL policy: legacy 'rules' shape is not supported; use 'permission' and 'prohibition'."
            )
        if "prohibition" not in prepped:
            prepped["prohibition"] = []
        if "duty" not in prepped:
            prepped["duty"] = []

        try:
            self.policy = ODRLPolicy(**prepped)
        except ValidationError as e:
            raise ValueError(f"Invalid ODRL policy: {e}") from e

    def _rule_groups(self):
        """Return the permission and prohibition groups in the policy.

        Returns:
            tuple: A pair of (permissions, prohibitions) lists.
        """
        permissions = self.policy.permission or []
        prohibitions = self.policy.prohibition or []
        return permissions, prohibitions

    @staticmethod
    def _rule_constraints(rule):
        """Normalize a rule's constraints into a list.

        Args:
            rule: ODRL rule object to inspect.

        Returns:
            list: Constraint objects, or an empty list when none are present.
        """
        constraints = rule.constraint
        if constraints is None:
            return []
        if isinstance(constraints, list):
            return constraints
        return [constraints]

    @staticmethod
    def _constraint_purposes(constraint):
        """Extract purpose values from a normalized ODRL constraint.

        Args:
            constraint: Constraint object or dictionary to inspect.

        Returns:
            list: Purpose strings extracted from the constraint.
        """
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
        """Check whether a rule's purpose constraint accepts the declared intent.

        Args:
            rule: ODRL rule being evaluated.
            declared_intent: Intent declared by the principal.

        Returns:
            tuple: (allowed, explanation) describing whether the declared intent is
                permitted by the rule's purpose constraint.
        """
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
        """Normalize a role IRI or alias to a canonical role token.

        Args:
            value: Raw role value from the policy or principal.

        Returns:
            str: Canonicalized role name used for comparison.
        """
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

    @staticmethod
    def _role_inherits(principal_role: str, assignee_role: str) -> bool:
        """Return whether principal_role inherits permissions of assignee_role.

        Args:
            principal_role: Canonical principal role token.
            assignee_role: Canonical assignee role token.

        Returns:
            bool: True when principal_role is configured as a superset role.
        """
        inheritance_map = {
            # Admins can operate under constrained policies assigned to narrower roles.
            "pii-data-governance-admin": {
                "pii-data-governance-admin",
                "privacy-compliance-analyst",
                "customer-support-specialist",
                "business-observer",
            }
        }
        inherited_roles = inheritance_map.get(principal_role, {principal_role})
        return assignee_role in inherited_roles

    @staticmethod
    def _normalize_policy_value(value: str | None) -> str:
        """Normalize a policy IRI or token to its terminal segment.

        Args:
            value: Raw policy value.

        Returns:
            str: Terminal segment of the value, with whitespace trimmed.
        """
        if not value:
            return ""

        normalized = value.strip().rstrip("/ ")
        for separator in ("#", "/", ":"):
            if separator in normalized:
                normalized = normalized.rsplit(separator, 1)[-1]

        return normalized

    def _permission_security_filters(self, rule, principal_role: str, declared_intent: str, action: str) -> dict:
        """Derive Cosmos DB security filters from a matching permission rule.

        Args:
            rule: Candidate permission rule.
            principal_role: Declared role of the principal.
            declared_intent: Declared intent of the principal.
            action: Requested action.

        Returns:
            dict: Policy-derived security filters for retrieval, or an empty dict.
        """
        role_allowed, _ = self._role_allows(rule, principal_role)
        if not role_allowed:
            return {}

        allowed, _ = self._constraint_allows(rule, declared_intent)
        if not allowed:
            return {}

        if action.lower() not in [candidate.lower() for candidate in rule.action]:
            return {}

        filters = {
            "policyUid": self._normalize_policy_value(self.policy.uid),
            "policyRole": self._canonical_role(rule.assignee or principal_role),
            "policyTarget": self._normalize_policy_value(rule.target),
            "policyAction": action.lower(),
        }

        allowed_purposes = []
        for constraint in self._rule_constraints(rule):
            allowed_purposes.extend(self._constraint_purposes(constraint))

        matched_purpose = next(
            (purpose for purpose in allowed_purposes if purpose.lower() == declared_intent.lower()),
            "",
        )
        if not matched_purpose and allowed_purposes:
            matched_purpose = allowed_purposes[0]
        if matched_purpose:
            filters["policyPurpose"] = matched_purpose

        if not filters["policyTarget"]:
            filters.pop("policyTarget")

        return {key: value for key, value in filters.items() if value}

    def derive_security_filters(self, principal_role: str, declared_intent: str, action: str) -> dict:
        """Derive security metadata filters from the first matching permission rule.

        Args:
            principal_role: Role declared by the principal.
            declared_intent: Purpose or intent declared by the principal.
            action: Requested action.

        Returns:
            dict: Security filter dict for Cosmos DB retrieval, or an empty dict when
                no permission rule matches.
        """
        permissions, _ = self._rule_groups()
        for rule in permissions:
            filters = self._permission_security_filters(rule, principal_role, declared_intent, action)
            if filters:
                return filters
        return {}

    def _role_allows(self, rule, principal_role: str) -> Tuple[bool, str]:
        """Check whether the principal role matches the rule assignee.

        Args:
            rule: ODRL rule being evaluated.
            principal_role: Role declared by the principal.

        Returns:
            tuple: (allowed, explanation) describing the role comparison result.
        """
        if not getattr(rule, "assignee", None):
            return True, "no assignee constraint -> permissive"

        principal_token = self._canonical_role(principal_role)
        assignee_token = self._canonical_role(rule.assignee)

        if principal_token and principal_token == assignee_token:
            return True, "principal role matched assignee"

        if principal_token and assignee_token and self._role_inherits(principal_token, assignee_token):
            return True, "principal role inherited assignee permissions"

        return False, "principal role did not match assignee"

    def evaluate(self, principal_role: str, declared_intent: str, action: str) -> Tuple[bool, dict]:
        """Evaluate whether the principal can take the requested action under the policy.

        The method checks all prohibitions first, then permission rules. If a
        prohibition matches the action and role and the declared intent is allowed,
        access is denied. Otherwise, a permission rule can grant access when the
        declared intent satisfies its purpose and role constraints.

        Args:
            principal_role: Role declared by the principal.
            declared_intent: Intent declared by the principal.
            action: Requested action to validate.

        Returns:
            tuple: (allowed, evaluation_dict) where the evaluation dict records the
                matched rules and reasoning trail.
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
            "satisfied": satisfied,
        }
        return satisfied, evaluation
