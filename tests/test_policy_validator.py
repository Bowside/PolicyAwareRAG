from policy_validator import PolicyPurposeValidator


def test_policy_validator_allows_matching_action_and_purpose():
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "type": "Set",
        "rules": [
            {
                "uid": "rule-1",
                "action": ["summarise"],
                "constraint": {"purpose": ["compliance_review", "triage"]},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("privacy-analyst", "compliance_review", "summarise")

    assert allowed is True
    assert detail["satisfied"] is True
    assert detail["matchedRules"] == ["rule-1"]


def test_policy_validator_rejects_non_matching_purpose():
    policy = {
        "@context": "https://www.w3.org/ns/odrl.jsonld",
        "type": "Set",
        "rules": [
            {
                "uid": "rule-2",
                "action": ["summarise"],
                "constraint": {"purpose": ["triage"]},
            }
        ],
    }

    validator = PolicyPurposeValidator(policy)
    allowed, detail = validator.evaluate("support-limited", "customer_support", "summarise")

    assert allowed is False
    assert detail["satisfied"] is False
