from graph_state import MultiAgentGraph, restrictive_agent, permissive_agent


def test_restrictive_agent_denies_disallowed_chunk():
    chunk = {"securityMetadata": {"disallow": True}}

    signal = restrictive_agent([chunk], {})

    assert signal["decision"].value == "Deny"


def test_multi_agent_graph_prefers_deny_over_allow():
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    chunks = [{"securityMetadata": {"disallow": True}}]

    result = graph.evaluate(chunks, {"satisfied": True})

    assert result["decision"] == "Deny"
    assert result["reasoning"]["tallies"]["deny"] == 1


def test_multi_agent_graph_can_allow_when_policy_satisfied():
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])

    result = graph.evaluate([], {"satisfied": True})

    assert result["decision"] in {"Allow", "Partial_Redaction"}
    assert result["reasoning"]["tallies"]["allow"] >= 1
