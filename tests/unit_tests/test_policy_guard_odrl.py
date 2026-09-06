import pytest

from app.policy_guard import (
    PolicyViolationError,
    evaluate_intent_against_odrl,
    infer_action_from_intent,
    infer_purpose_from_intent,
    normalize_policy_action,
    normalize_policy_purpose,
    normalize_policy_role,
)


@pytest.mark.parametrize(
    ("raw_role", "expected"),
    [
        ("business-observer", "business-observer"),
        ("Business Observer", "business-observer"),
        (" BUSINESS-OBSERVER ", "business-observer"),
        ("urn:policyaware:role:business-observer", "business-observer"),
        ("URN:POLICYAWARE:ROLE:PRIVACY-COMPLIANCE-ANALYST", "privacy-compliance-analyst"),
        ("customer support specialist", "customer-support-specialist"),
        ("pii-data-governance-admin", "pii-data-governance-admin"),
        (None, ""),
    ],
)
def test_normalize_policy_role(raw_role, expected):
    assert normalize_policy_role(raw_role) == expected


@pytest.mark.parametrize(
    ("raw_action", "expected"),
    [
        ("summarise", "summarise"),
        ("SUMMARIZE", "summarize"),
        (" review findings ", "review_findings"),
        (None, ""),
        ("export data", "export_data"),
    ],
)
def test_normalize_policy_action(raw_action, expected):
    assert normalize_policy_action(raw_action) == expected


@pytest.mark.parametrize(
    ("raw_purpose", "expected"),
    [
        ("routing", "routing"),
        ("Privacy Review", "privacy_review"),
        (" COMPLIANCE REVIEW ", "compliance_review"),
        (None, ""),
        ("case management", "case_management"),
    ],
)
def test_normalize_policy_purpose(raw_purpose, expected):
    assert normalize_policy_purpose(raw_purpose) == expected


@pytest.mark.parametrize(
    ("intent", "expected"),
    [
        ("Export the records", "export"),
        ("Download the report", "export"),
        ("Share the customer list", "export"),
        ("Mask the email address", "redact"),
        ("Anonymize the response", "redact"),
        ("Summarize the thread", "summarise"),
        ("Audit the activity", "audit"),
        ("Find matching documents", "retrieve"),
    ],
)
def test_infer_action_from_intent(intent, expected):
    assert infer_action_from_intent(intent) == expected


@pytest.mark.parametrize(
    ("intent", "expected"),
    [
        ("Review metadata fields", "metadata_review"),
        ("Check routing details", "routing"),
        ("Triage the request", "triage"),
        ("Handle this support case", "customer_support"),
        ("Update the case record", "case_management"),
        ("Investigate the incident", "incident_triage"),
        ("Review compliance risks", "compliance_review"),
        ("Investigate possible fraud", "fraud_detection"),
        ("Perform a security review", "security_review"),
        ("Complete a privacy review", "privacy_review"),
    ],
)
def test_infer_purpose_from_intent(intent, expected):
    assert infer_purpose_from_intent(intent) == expected


OBSERVER_ALLOWED = [
    ("business-observer", purpose, action)
    for purpose in ("metadata_review", "routing", "triage")
    for action in ("summarise", "summarize", "retrieve")
]

SUPPORT_ALLOWED = [
    ("customer-support-specialist", purpose, action)
    for purpose in ("customer_support", "case_management", "incident_triage")
    for action in ("summarise", "summarize", "retrieve", "audit")
]

PRIVACY_ALLOWED = [
    ("privacy-compliance-analyst", purpose, action)
    for purpose in ("compliance_review", "fraud_detection", "security_review", "privacy_review")
    for action in ("summarise", "summarize", "retrieve", "audit", "redact")
]

ADMIN_ALLOWED = [
    ("pii-data-governance-admin", "metadata_review", action)
    for action in ("summarise", "summarize", "retrieve", "audit", "redact", "export")
]


@pytest.mark.parametrize("role,purpose,action", OBSERVER_ALLOWED + SUPPORT_ALLOWED + PRIVACY_ALLOWED + ADMIN_ALLOWED)
def test_odrl_allows_policy_defined_role_purpose_action(role, purpose, action):
    assert evaluate_intent_against_odrl(
        f"Perform {action} for {purpose}.",
        [role],
        purpose=purpose,
        action=action,
    ) is True


@pytest.mark.parametrize(
    ("role", "purpose", "action"),
    [
        ("business-observer", "routing", "export"),
        ("business-observer", "routing", "redact"),
        ("customer-support-specialist", "customer_support", "export"),
        ("customer-support-specialist", "incident_triage", "redact"),
        ("privacy-compliance-analyst", "privacy_review", "export"),
        ("business-observer", "compliance_review", "retrieve"),
    ],
)
def test_odrl_denies_policy_violations(role, purpose, action):
    with pytest.raises(PolicyViolationError, match="Policy denial"):
        evaluate_intent_against_odrl(
            f"Perform {action} for {purpose}.",
            [role],
            purpose=purpose,
            action=action,
        )


