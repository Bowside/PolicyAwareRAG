"""Policy-aware validation and redaction utilities for the RAG pipeline.

These helpers enforce the repository's ODRL permission model before retrieval and
before returning an answer to the client. The policy set is defined in the
odrl_policies directory and is evaluated against the caller's role set and the
requested usage purpose.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Sequence

_POLICY_ROLE_PRIORITY = {
    "business-observer": 0,
    "customer-support-specialist": 1,
    "privacy-compliance-analyst": 2,
    "pii-data-governance-admin": 3,
}


class PolicyViolationError(ValueError):
    """Raised when a request or generated response violates the active ODRL policy."""


def normalize_policy_role(value: str | None) -> str:
    """Normalize a role value to the canonical policy role identifier.

    Args:
        value: A raw role string or URN-formatted role identifier.

    Returns:
        The normalized role in the repository's policy format.
    """
    if value is None:
        return ""
    cleaned = str(value).strip().lower().replace(" ", "-")
    if cleaned.startswith("urn:policyaware:role:"):
        cleaned = cleaned.removeprefix("urn:policyaware:role:")
    return cleaned


def normalize_policy_action(value: str | None) -> str:
    """Normalize an action name so policy rules and runtime requests match.

    Args:
        value: A raw action string such as "summarise" or "export".

    Returns:
        A canonical action string that matches the policy metadata.
    """
    if value is None:
        return ""
    cleaned = str(value).strip().lower().replace(" ", "_")
    return cleaned


def normalize_policy_purpose(value: str | None) -> str:
    """Normalize a purpose value used by ODRL constraints.

    Args:
        value: A raw purpose string such as "routing" or "privacy_review".

    Returns:
        A normalized purpose value that matches the policy definition.
    """
    if value is None:
        return ""
    cleaned = str(value).strip().lower().replace(" ", "_")
    return cleaned


def _policies_path() -> Path:
    """Return the repository path that contains the ODRL policy definitions."""
    return Path(__file__).resolve().parent.parent / "odrl_policies"


def load_odrl_policies() -> list[dict[str, Any]]:
    """Load all ODRL policy documents from the repository policy directory.

    Returns:
        A list of parsed ODRL policy dictionaries.
    """
    policy_files = sorted(_policies_path().glob("*.json"))
    policies: list[dict[str, Any]] = []
    for policy_file in policy_files:
        with policy_file.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            policies.append(data)
    return policies


def _matches_policy_role(role: str, policy_entry: dict[str, Any]) -> bool:
    """Check whether a given policy entry matches a normalized role.

    Args:
        role: The caller role to check.
        policy_entry: A policy permission or prohibition entry.

    Returns:
        True when the policy entry applies to the supplied role.
    """
    assignee = policy_entry.get("assignee")
    return normalize_policy_role(assignee) == normalize_policy_role(role)


def _policy_permissions_for_role(role: str) -> list[dict[str, Any]]:
    """Collect the permissions that apply to a specific role.

    Args:
        role: The role name to inspect.

    Returns:
        The list of matching permission entries from the ODRL policies.
    """
    normalized_role = normalize_policy_role(role)
    permissions: list[dict[str, Any]] = []
    for policy in load_odrl_policies():
        for permission in policy.get("permission", []):
            if _matches_policy_role(normalized_role, permission):
                permissions.append(permission)
    return permissions


def _policy_prohibitions_for_role(role: str) -> list[dict[str, Any]]:
    """Collect the prohibitions that apply to a specific role.

    Args:
        role: The role name to inspect.

    Returns:
        The list of matching prohibition entries from the ODRL policies.
    """
    normalized_role = normalize_policy_role(role)
    prohibitions: list[dict[str, Any]] = []
    for policy in load_odrl_policies():
        for prohibition in policy.get("prohibition", []):
            if _matches_policy_role(normalized_role, prohibition):
                prohibitions.append(prohibition)
    return prohibitions


def infer_action_from_intent(intent: str) -> str:
    """Infer the most likely policy action from the user's stated intent.

    Args:
        intent: The raw user request text.

    Returns:
        The best matching ODRL action for the request.
    """
    lowered = (intent or "").lower()
    if any(token in lowered for token in ["export", "download", "share"]):
        return "export"
    if any(token in lowered for token in ["redact", "mask", "anonymize"]):
        return "redact"
    if any(token in lowered for token in ["summar", "summary", "review", "analyze"]):
        return "summarise"
    if any(token in lowered for token in ["audit", "investigate", "fraud", "compliance"]):
        return "audit"
    return "retrieve"


def infer_purpose_from_intent(intent: str) -> str:
    """Infer the ODRL purpose from the intent text when one is not provided.

    Args:
        intent: The raw user request text.

    Returns:
        The best matching ODRL purpose category.
    """
    lowered = (intent or "").lower()
    keyword_map = {
        "metadata": "metadata_review",
        "routing": "routing",
        "triage": "triage",
        "support": "customer_support",
        "case": "case_management",
        "incident": "incident_triage",
        "compliance": "compliance_review",
        "fraud": "fraud_detection",
        "security": "security_review",
        "privacy": "privacy_review",
    }
    for token, purpose in keyword_map.items():
        if token in lowered:
            return purpose
    return "metadata_review"


def _choose_strictest_role(roles: Sequence[str]) -> str:
    """Choose the highest-restriction role for conservative validation.

    Args:
        roles: The roles that are available to the caller.

    Returns:
        The most restrictive role according to the policy hierarchy.
    """
    normalized_roles = [normalize_policy_role(role) for role in roles if normalize_policy_role(role)]
    if not normalized_roles:
        return ""
    return min(normalized_roles, key=lambda role: _POLICY_ROLE_PRIORITY.get(role, 99))


def evaluate_intent_against_odrl(
    intent: str,
    user_roles: Sequence[str] | None,
    purpose: str | None = None,
    action: str | None = None,
) -> bool:
    """Validate an intent against the configured ODRL permissions.

    Args:
        intent: The user request text to validate.
        user_roles: The roles available to the caller.
        purpose: The policy purpose of the request, if supplied.
        action: The requested action, if supplied.

    Returns:
        True when the request is authorized under the active ODRL policies.

    Raises:
        PolicyViolationError: If the intent is empty or unauthorized.
    """
    requested_intent = (intent or "").strip()
    if not requested_intent:
        raise PolicyViolationError("Policy denial: no user intent was supplied.")

    roles = [normalize_policy_role(role) for role in (user_roles or []) if normalize_policy_role(role)]
    if not roles:
        raise PolicyViolationError("Policy denial: no user roles are available for ODRL evaluation.")

    normalized_action = normalize_policy_action(action or infer_action_from_intent(requested_intent))
    normalized_purpose = normalize_policy_purpose(purpose or infer_purpose_from_intent(requested_intent))

    for role in roles:
        permissions = _policy_permissions_for_role(role)
        if not permissions:
            continue

        has_permission = False
        for permission in permissions:
            permitted_actions = [normalize_policy_action(a) for a in permission.get("action", [])]
            if normalized_action not in permitted_actions:
                continue

            constraint = permission.get("constraint")
            if constraint and constraint.get("leftOperand") == "purpose":
                rule_purpose = normalize_policy_purpose(constraint.get("rightOperand"))
                if normalized_purpose and rule_purpose and rule_purpose != normalized_purpose:
                    continue

            has_permission = True
            break

        if has_permission:
            prohibitions = _policy_prohibitions_for_role(role)
            for prohibition in prohibitions:
                prohibited_actions = [normalize_policy_action(a) for a in prohibition.get("action", [])]
                if normalized_action in prohibited_actions:
                    raise PolicyViolationError(
                        f"Policy denial: role '{role}' is prohibited from '{normalized_action}' actions."
                    )
            return True

    raise PolicyViolationError(
        "Policy denial: the supplied user roles do not authorize this request under the active ODRL policies."
    )


def _contains_sensitive_data(value: str) -> bool:
    """Check whether a generated response includes common sensitive data patterns.

    Args:
        value: The response text to inspect.

    Returns:
        True when common PII-like values are present.
    """
    patterns = [
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b\d{10}\b",
        r"\b(?:ssn|tax id|social security)\b",
    ]
    lowered = (value or "").lower()
    return any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns)


def redact_response_for_role(
    response: str,
    role: str | Sequence[str] | None,
    purpose: str | None = None,
) -> str:
    """Apply the least-privilege redaction routine for the supplied role(s).

    Args:
        response: The unredacted response text.
        role: One or more roles to use for redaction decisions.
        purpose: The policy purpose for the current request.

    Returns:
        The redacted response text.
    """
    if not response:
        return response

    roles: list[str] = []
    if isinstance(role, str):
        roles = [normalize_policy_role(role)]
    elif role is not None:
        roles = [normalize_policy_role(item) for item in role if normalize_policy_role(item)]

    if not roles:
        return response

    effective_role = _choose_strictest_role(roles)
    if effective_role in {"business-observer", "customer-support-specialist"}:
        redacted = re.sub(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[REDACTED_EMAIL]",
            response,
        )
        redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", redacted)
        return redacted
    return response


def spokesperson_guardrail(
    context: Sequence[str] | None,
    generated_response: str,
    user_roles: Sequence[str] | None,
    purpose: str | None = None,
) -> str:
    """Guardrail the model output before it is returned to the caller.

    This acts as the post-generation "spokesperson" layer: it verifies that the
    answer does not reveal information forbidden by the user's least-privileged
    role and applies explicit redaction when required.

    Args:
        context: The retrieved context used to create the answer.
        generated_response: The model-generated answer.
        user_roles: The roles that are available to the caller.
        purpose: The request purpose for policy evaluation.

    Returns:
        The final response text after policy-based redaction checks.
    """
    if not generated_response:
        return generated_response

    roles = [normalize_policy_role(role) for role in (user_roles or []) if normalize_policy_role(role)]
    if not roles:
        raise PolicyViolationError("Policy denial: no user roles are available for spokesperson validation.")

    effective_role = _choose_strictest_role(roles)
    if effective_role in {"business-observer", "customer-support-specialist"} and _contains_sensitive_data(generated_response):
        return redact_response_for_role(generated_response, effective_role, purpose)

    return redact_response_for_role(generated_response, effective_role, purpose)
