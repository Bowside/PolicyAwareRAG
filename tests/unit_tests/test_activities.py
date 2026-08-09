import activities


def test_build_context_snippets_uses_multiple_text_fields():
    retrieved = [
        {"id": "chunk-1", "text": "This is the actual retrieved content.", "subject": "Quarterly review"},
        {"id": "chunk-2", "body": "Another chunk with policy context.", "from": "ops@example.com"},
    ]

    rendered = activities._build_context_snippets(retrieved)

    assert "This is the actual retrieved content." in rendered
    assert "Another chunk with policy context." in rendered


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

    assert "temporarily unavailable" in result
    assert "AI service unavailable" in result


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

    assert "temporarily unavailable" in result
    assert "AI service unavailable" in result
