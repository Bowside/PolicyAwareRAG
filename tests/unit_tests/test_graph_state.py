"""Unit tests for the multi-agent graph decision logic.

These tests validate deny-veto behavior, allow decisions when policy satisfaction
is present, and JSON serialization of the graph output.
"""

from graph_state import MultiAgentGraph, permissive_agent, restrictive_agent


def test_restrictive_agent_denies_disallowed_chunk():
    """The restrictive agent should deny any chunk marked disallowed."""
    chunk = {"securityMetadata": {"disallow": True}}

    signal = restrictive_agent([chunk], {})

    assert signal["decision"] == "Deny"


def test_multi_agent_graph_prefers_deny_over_allow():
    """Deny votes should override allow votes when both are present."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    chunks = [{"securityMetadata": {"disallow": True}}]

    result = graph.evaluate(chunks, {"satisfied": True})

    assert result["decision"] == "Deny"
    assert result["reasoning"]["tallies"]["deny"] == 1
    assert result["reasoning"]["signals"][0]["decision"] == "Deny"


def test_multi_agent_graph_can_allow_when_policy_satisfied():
    """A satisfied policy state should allow the graph to return an allow-like decision."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])

    result = graph.evaluate([], {"satisfied": True})

    assert result["decision"] in {"Allow", "Partial_Redaction"}
    assert result["reasoning"]["tallies"]["allow"] >= 1


def test_multi_agent_graph_output_is_json_serializable():
    """The graph output should be serializable for audit and transport payloads."""
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])

    result = graph.evaluate([], {"satisfied": True})

    import json

    json.dumps(result)
