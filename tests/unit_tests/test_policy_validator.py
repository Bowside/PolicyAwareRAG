from policy_validator import PolicyPurposeValidator


def test_policy_validator_allows_matching_action_and_purpose():
    """Verify matching role, purpose, and action are allowed."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:compliance-review",
                "action": ["summarise"],
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("privacy-analyst", "compliance_review", "summarise")

    assert allowed is True
    assert detail["satisfied"] is True
    assert detail["matchedRules"] == ["urn:policyaware:permission:test:compliance-review"]


def test_policy_validator_rejects_non_matching_purpose():
    """Verify an unmatched purpose is rejected."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:triage",
                "action": ["summarise"],
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "triage"},
            }
        ],
        "prohibition": [],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("support-limited", "customer_support", "summarise")

    assert allowed is False
    assert detail["satisfied"] is False


def test_policy_validator_rejects_matching_prohibition():
    """Verify a matching prohibition blocks the action."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:export",
                "action": ["export"],
            }
        ],
        "prohibition": [
            {
                "uid": "urn:policyaware:prohibition:test:no-export",
                "action": ["export"],
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("customer-support-specialist", "customer_support", "export")

    assert allowed is False
    assert detail["satisfied"] is False
    assert detail["matchedRules"][0] == "urn:policyaware:prohibition:test:no-export"


def test_policy_validator_enforces_assignee_role_match():
    """Verify the validator enforces the assignee role."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:role-bound",
                "action": ["summarise"],
                "assignee": "urn:policyaware:role:privacy-compliance-analyst",
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("privacy-compliance-analyst", "compliance_review", "summarise")

    assert allowed is True
    assert detail["satisfied"] is True


def test_policy_validator_denies_when_assignee_role_does_not_match():
    """Verify a non-matching assignee role is denied."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:role-bound",
                "action": ["summarise"],
                "assignee": "urn:policyaware:role:privacy-compliance-analyst",
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("customer-support-specialist", "compliance_review", "summarise")

    assert allowed is False
    assert detail["satisfied"] is False


def test_policy_validator_allows_legacy_role_aliases():
    """Verify legacy role aliases map to the canonical role."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "permission": [
            {
                "uid": "urn:policyaware:permission:test:legacy-role-alias",
                "action": ["summarise"],
                "assignee": "urn:policyaware:role:privacy-compliance-analyst",
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("privacy-analyst", "compliance_review", "summarise")

    assert allowed is True
    assert detail["satisfied"] is True


def test_policy_validator_derives_security_filters_from_policy():
    """Verify security filters are derived from the policy document."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "uid": "urn:policyaware:policy:privacy-compliance-analyst",
        "permission": [
            {
                "uid": "urn:policyaware:permission:privacy-compliance-analyst:compliance-review",
                "target": "urn:policyaware:asset:pii-rag-corpus",
                "action": ["summarise"],
                "assignee": "urn:policyaware:role:privacy-compliance-analyst",
                "constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    filters = validator.derive_security_filters("privacy-compliance-analyst", "compliance_review", "summarise")

    assert filters == {
        "policyUid": "privacy-compliance-analyst",
        "policyRole": "privacy-compliance-analyst",
        "policyTarget": "pii-rag-corpus",
        "policyAction": "summarise",
        "policyPurpose": "compliance_review",
    }


def test_policy_validator_rejects_legacy_rules_shape():
    """Verify legacy rules-only policies are rejected."""
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "@type": "Set",
        "rules": [
            {
                "uid": "rule-legacy",
                "action": ["summarise"],
            }
        ],
    }

    try:
        PolicyPurposeValidator(policy)
    except ValueError as exc:
        assert "legacy 'rules' shape" in str(exc)
    else:
        raise AssertionError("Legacy rules-only policy should be rejected")
