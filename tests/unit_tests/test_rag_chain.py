"""Test RAG configuration, retrieval, policy enforcement, and audit behavior."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from app.audit_logger import AuditLogger
from app.policy_guard import (
    PolicyViolationError,
    evaluate_intent_against_odrl,
    load_odrl_policies,
    redact_response_for_role,
)
from app.rag_chain import (
    build_rag_chain,
    build_vector_store,
    get_cosmos_settings,
    get_foundry_settings,
    retrieve_documents,
)
from tests.performance_evaluation.run_evaluations import extract_step_metrics


def test_get_foundry_settings_uses_environment_values(monkeypatch):
    """Ensure Foundry settings are loaded from environment variables.

    Args:
        monkeypatch: Pytest fixture used to set environment variables.
    """
    monkeypatch.setenv("FOUNDRY_ENDPOINT", "https://example.services.ai.azure.com/models")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")
    monkeypatch.setenv("FOUNDRY_CHAT_MODEL", "gpt-4o-mini")
    monkeypatch.setenv("FOUNDRY_EMBEDDING_MODEL", "text-embedding-3-small")

    settings = get_foundry_settings()

    assert settings["endpoint"] == "https://example.services.ai.azure.com/models"
    assert settings["api_key"] == "test-key"
    assert settings["chat_model"] == "gpt-4o-mini"
    assert settings["embedding_model"] == "text-embedding-3-small"


def test_extract_step_metrics_preserves_named_audit_steps():
    """Ensure evaluation records retain names and measured step latency."""
    metrics = extract_step_metrics(
        {
            "pipelineSteps": [
                {
                    "stepName": "ContextRetrieval",
                    "executionStatus": "ALLOWED",
                    "telemetry": {"latencyMs": 12.5, "documentMatchCount": 3},
                },
                {
                    "step_name": "SpokespersonValidation",
                    "execution_status": "ALLOWED",
                    "telemetry": {"elapsedMs": 4.25},
                },
            ],
        },
        "Summarize the request.",
    )

    assert [step["stepName"] for step in metrics] == [
        "ContextRetrieval",
        "SpokespersonValidation",
    ]
    assert [step["latency_ms"] for step in metrics] == [12.5, 4.25]


def test_get_foundry_settings_uses_defaults_when_missing(monkeypatch):
    """Ensure default Foundry values are used when the environment is empty.

    Args:
        monkeypatch: Pytest fixture used to clear environment variables.
    """
    monkeypatch.delenv("FOUNDRY_ENDPOINT", raising=False)
    monkeypatch.delenv("FOUNDRY_API_KEY", raising=False)
    monkeypatch.delenv("FOUNDRY_CHAT_MODEL", raising=False)
    monkeypatch.delenv("FOUNDRY_EMBEDDING_MODEL", raising=False)

    settings = get_foundry_settings()

    assert settings["endpoint"] is None
    assert settings["api_key"] is None
    assert settings["chat_model"] == "gpt-4o-mini"
    assert settings["embedding_model"] == "text-embedding-3-small"


def test_get_cosmos_settings_uses_environment_values(monkeypatch):
    """Ensure Cosmos settings are loaded from environment variables.

    Args:
        monkeypatch: Pytest fixture used to set environment variables.
    """
    monkeypatch.setenv("COSMOSDB_ENDPOINT", "https://example.documents.azure.com:443/")
    monkeypatch.setenv("COSMOSDB_KEY", "test-cosmos-key")
    monkeypatch.setenv("COSMOSDB_DATABASE", "policy_rag_db")
    monkeypatch.setenv("COSMOSDB_COLLECTION", "EnronEmailVectorStore")
    monkeypatch.setenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

    settings = get_cosmos_settings()

    assert settings["endpoint"] == "https://example.documents.azure.com:443/"
    assert settings["key"] == "test-cosmos-key"
    assert settings["database"] == "policy_rag_db"
    assert settings["container"] == "EnronEmailVectorStore"
    assert settings["embedding_model"] == "all-MiniLM-L6-v2"


@patch("app.rag_chain.get_cosmos_container")
def test_build_vector_store_uses_cosmos_container(mock_get_cosmos_container, monkeypatch):
    """Ensure the vector store is built from the configured Cosmos container.

    Args:
        mock_get_cosmos_container: Mocked Cosmos container factory.
        monkeypatch: Pytest fixture used to set Cosmos configuration.
    """
    monkeypatch.setenv("COSMOSDB_ENDPOINT", "https://example.documents.azure.com:443/")
    monkeypatch.setenv("COSMOSDB_KEY", "test-cosmos-key")
    monkeypatch.setenv("COSMOSDB_DATABASE", "policy_rag_db")
    monkeypatch.setenv("COSMOSDB_COLLECTION", "EnronEmailVectorStore")

    result = build_vector_store()

    mock_get_cosmos_container.assert_called_once()
    assert result is mock_get_cosmos_container.return_value


@patch("app.rag_chain.ChatOpenAI")
@patch("app.rag_chain.StateGraph")
@patch("app.rag_chain.ChatPromptTemplate.from_template")
def test_build_rag_chain_instantiates_graph_components(
    mock_prompt_template,
    mock_state_graph,
    mock_chat_openai,
    monkeypatch,
):
    """Ensure the LangGraph pipeline is configured with the expected nodes.

    Args:
        mock_prompt_template: Mocked prompt template factory.
        mock_state_graph: Mocked LangGraph state graph.
        mock_chat_openai: Mocked Foundry chat client.
        monkeypatch: Pytest fixture used to set Foundry configuration.
    """
    monkeypatch.setenv("FOUNDRY_ENDPOINT", "https://example.services.ai.azure.com/models")
    monkeypatch.setenv("FOUNDRY_API_KEY", "test-key")

    mock_graph = mock_state_graph.return_value
    mock_compiled = mock_graph.compile.return_value

    result = build_rag_chain()

    mock_chat_openai.assert_called_once()
    mock_prompt_template.assert_called_once()
    mock_graph.add_node.assert_called()
    mock_graph.add_edge.assert_called()
    mock_graph.set_entry_point.assert_called_once_with("retrieve")
    assert result is mock_compiled


def test_evaluate_intent_denies_unapproved_export_for_business_observer():
    """Ensure unauthorized export requests are denied before retrieval."""
    with pytest.raises(PolicyViolationError, match="Policy denial"):
        evaluate_intent_against_odrl(
            "Export the personal emails for all customers.",
            ["business-observer"],
            purpose="routing",
            action="export",
        )


def test_redact_response_masks_email_for_limited_role():
    """Ensure limited roles receive email redaction in their responses."""
    redacted = redact_response_for_role(
        "Contact jane.doe@example.com for approval.",
        "business-observer",
    )

    assert "example.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted


def test_load_odrl_policies_includes_expected_roles_and_permissions():
    """Ensure the repository ODRL policy set includes all expected roles and rules."""
    policies = load_odrl_policies()
    roles = {
        permission["assignee"].removeprefix("urn:policyaware:role:")
        for policy in policies
        for permission in policy.get("permission", [])
        if "assignee" in permission
    }

    assert roles == {
        "business-observer",
        "customer-support-specialist",
        "privacy-compliance-analyst",
        "pii-data-governance-admin",
    }
    assert any(
        policy.get("uid") == "urn:policyaware:policy:privacy-compliance-analyst"
        for policy in policies
    )


def test_evaluate_intent_allows_privacy_analyst_for_compliance_review():
    """Ensure the repository ODRL policy authorizes a privacy review for the matching role."""
    assert evaluate_intent_against_odrl(
        "Review compliance risks from the PII dataset.",
        ["privacy-compliance-analyst"],
        purpose="compliance_review",
        action="summarise",
    ) is True


def test_audit_logger_emits_privacy_safe_schema():
    """Ensure the audit log stores a minimal, pseudonymized schema without raw payload data."""
    logger = AuditLogger(endpoint="https://example.documents.azure.com:443/", key="test-key")
    mock_container = MagicMock()
    logger._container = mock_container

    logger.emit(
        step_name="IntentValidation",
        execution_status="ALLOWED",
        policy_metadata={"roles": ["business-observer"], "purpose": "routing", "action": "retrieve"},
        telemetry={"latencyMs": 42, "documentMatchCount": 5},
        correlation_id="trace-123",
        user_id="tenant-user-42",
        prompt_text="Export all customer records.",
        response_text="The answer contains customer email addresses.",
        document_ids=["doc-1", "doc-2"],
        reason="Policy validated this request.",
    )

    mock_container.upsert_item.assert_called_once()
    entry = mock_container.upsert_item.call_args.kwargs["body"]

    assert set(entry) >= {
        "id",
        "timestamp",
        "traceId",
        "correlationId",
        "stepName",
        "executionStatus",
        "policyMetadata",
        "telemetry",
        "userPseudonym",
        "pipelineSteps",
        "stepCount",
    }
    assert entry["traceId"] == "trace-123"
    assert entry["correlationId"] == "trace-123"
    assert entry["stepName"] == "RequestAudit"
    assert entry["executionStatus"] == "ALLOWED"
    assert entry["userPseudonym"] != "tenant-user-42"
    assert entry["userQuery"] == "Export all customer records."
    assert "customer email addresses" not in json.dumps(entry)
    assert "responseHash" not in json.dumps(entry)
    assert entry["stepCount"] >= 1
    assert any(step["stepName"] == "IntentValidation" for step in entry["pipelineSteps"])
    assert entry["pipelineSteps"][0]["candidateDocumentIds"] == ["doc-1", "doc-2"]


@patch("app.rag_chain.get_cosmos_container")
@patch("app.rag_chain.embed_query")
def test_retrieve_documents_filters_by_security_metadata(mock_embed_query, mock_get_cosmos_container):
    """Ensure role metadata filtering removes unauthorized records and keeps safe ones.

    Args:
        mock_embed_query: Mocked embedding function.
        mock_get_cosmos_container: Mocked Cosmos container factory.
    """
    mock_embed_query.return_value = [0.1, 0.2, 0.3]
    mock_get_cosmos_container.return_value.query_items.return_value = [
        {
            "id": "allowed",
            "subject": "Allowed",
            "body": "Allowed body",
            "securityMetadata": {"policyRole": ["privacy-compliance-analyst"]},
        },
        {
            "id": "blocked",
            "subject": "Blocked",
            "body": "Blocked body",
            "securityMetadata": {"policyRole": ["business-observer"]},
        },
        {
            "id": "no-metadata",
            "subject": "No metadata",
            "body": "No metadata body",
        },
    ]

    docs = retrieve_documents(
        "Summarize this content.",
        user_roles=["privacy-compliance-analyst"],
        purpose="compliance_review",
        action="retrieve",
    )

    assert [doc.metadata["source"] for doc in docs] == ["allowed", "no-metadata"]


