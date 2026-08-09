from graph_state import MultiAgentGraph, restrictive_agent, permissive_agent


def test_restrictive_agent_denies_disallowed_chunk():
    """Verify the restrictive agent denies chunks tagged as disallowed."""
    chunk = {"securityMetadata": {"disallow": True}}

    signal = restrictive_agent([chunk], {})

    assert signal["decision"] == "Deny"


def test_multi_agent_graph_prefers_deny_over_allow():
    """Verify deny votes override allow votes in the agent graph."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    chunks = [{"securityMetadata": {"disallow": True}}]

    result = graph.evaluate(chunks, {"satisfied": True})

    assert result["decision"] == "Deny"
    assert result["reasoning"]["tallies"]["deny"] == 1
    assert result["reasoning"]["signals"][0]["decision"] == "Deny"


def test_multi_agent_graph_can_allow_when_policy_satisfied():
    """Verify the graph can allow when policy state is satisfied."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])

    result = graph.evaluate([], {"satisfied": True})

    assert result["decision"] in {"Allow", "Partial_Redaction"}
    assert result["reasoning"]["tallies"]["allow"] >= 1


def test_multi_agent_graph_output_is_json_serializable():
    """Verify the agent graph output can be serialized to JSON."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])

    result = graph.evaluate([], {"satisfied": True})

    import json

    json.dumps(result)
