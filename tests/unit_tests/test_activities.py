import activities


def test_generate_response_activity_returns_fallback_when_ai_call_fails(monkeypatch):
    def raise_error(*args, **kwargs):
        raise RuntimeError("AI service unavailable")

    monkeypatch.setattr(activities, "_chat_with_ai_foundry", raise_error)

    result = activities.GenerateResponseActivity(
        {
            "retrieved": [{"id": "chunk-1", "content": "Policy-safe context"}],
            "query_text": "Summarise the approved context.",
            "policy_evaluation": {},
            "principal": {"role": "privacy-compliance-analyst", "declaredIntent": "privacy_review"},
            "action": "summarise",
        }
    )

    assert result == "The response service is temporarily unavailable. Please try again later."


def test_generate_redacted_response_activity_returns_fallback_when_ai_call_fails(monkeypatch):
    def raise_error(*args, **kwargs):
        raise RuntimeError("AI service unavailable")

    monkeypatch.setattr(activities, "_chat_with_ai_foundry", raise_error)

    result = activities.GenerateRedactedResponseActivity(
        {
            "retrieved": [{"id": "chunk-1", "content": "Sensitive but redacted context"}],
            "query_text": "Summarise the redacted excerpts.",
        }
    )

    assert result == "The response service is temporarily unavailable. Please try again later."
