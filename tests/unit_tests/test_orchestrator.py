"""Unit tests covering the orchestrator workflow and embedding fallback logic.

These tests validate the durable orchestration behavior when policy evaluation
fails or succeeds, and confirm that short query vectors are expanded to the
configured embedding dimensionality before retrieval.
"""

import importlib
import sys
import types

import pytest


def _install_azure_stubs():
	"""Register minimal Azure SDK stubs needed for importing the orchestrator module."""
	azure_pkg = types.ModuleType("azure")
	azure_pkg.__path__ = []

	cosmos_mod = types.ModuleType("azure.cosmos")

	class _FakeContainer:
		def query_items(self, *args, **kwargs):
			return []

	class _FakeDatabaseClient:
		def get_container_client(self, *args, **kwargs):
			return _FakeContainer()

	class _FakeCosmosClient:
		def __init__(self, *args, **kwargs):
			pass

		def get_database_client(self, *args, **kwargs):
			return _FakeDatabaseClient()

	cosmos_mod.CosmosClient = _FakeCosmosClient

	durable_mod = types.ModuleType("azure.durable_functions")
	durable_mod.DurableOrchestrationContext = object
	durable_mod.Orchestrator = types.SimpleNamespace(create=lambda func: func)

	sys.modules["azure"] = azure_pkg
	sys.modules["azure.cosmos"] = cosmos_mod
	sys.modules["azure.durable_functions"] = durable_mod


class _FakeContext:
	"""Simple durable context stub that records activity calls for the orchestrator tests."""

	def __init__(self, payload):
		self._payload = payload
		self.activity_calls = []

	def get_input(self):
		return self._payload

	def call_activity(self, name, payload):
		self.activity_calls.append((name, payload))
		return {"name": name, "payload": payload}


def _load_orchestrator():
	"""Import the orchestrator module with fresh Azure stubs for each test case."""
	_install_azure_stubs()
	for module_name in ["orchestrator", "retriever", "graph_state", "policy_validator"]:
		sys.modules.pop(module_name, None)
	return importlib.import_module("orchestrator")


def test_orchestrator_denies_before_retrieval_when_policy_validator_declines(monkeypatch):
	"""The orchestration should stop before retrieval when policy validation denies the request."""
	orchestrator = _load_orchestrator()

	class _FailingRetriever:
		def __init__(self, *args, **kwargs):
			raise AssertionError("retriever should not be initialized when policy validation fails")

	monkeypatch.setattr(orchestrator, "ConflictAwareRetriever", _FailingRetriever)

	context = _FakeContext(
		{
			"principal": {"role": "customer-support-specialist", "declaredIntent": "customer_support"},
			"query_text": "Summarise the privacy review emails",
			"action": "summarise",
						"query_embedding": [0.0] * 16,
			"odrl_policy": {
				"@context": "https://www.w3.org/ns/odrl.jsonld",
				"@type": "Set",
				"permission": [
					{
						"uid": "urn:policyaware:permission:test:deny",
						"action": ["summarise"],
						"constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
					}
				],
			},
		}
	)

	generator = orchestrator.orchestrator_function(context)
	yielded = next(generator)
	assert yielded["name"] == "StoreAuditEventActivity"
	assert context.activity_calls == [("StoreAuditEventActivity", yielded["payload"])]
	with pytest.raises(StopIteration) as excinfo:
		generator.send({"status": "ok"})

	result = excinfo.value.value
	assert result["status"] == "denied"
	assert "policyEvaluation" in result


def test_orchestrator_retrieval_uses_empty_security_filters(monkeypatch):
	"""An approved request should still pass an empty security filter set to the retriever."""
	orchestrator = _load_orchestrator()
	retriever_calls = {}

	class _RecordingRetriever:
		def __init__(self, *args, **kwargs):
			retriever_calls["container_name"] = kwargs.get("container_name")

		def retrieve(self, query_embedding, security_filters, top_k=10):
			retriever_calls["query_embedding"] = query_embedding
			retriever_calls["security_filters"] = security_filters
			retriever_calls["top_k"] = top_k
			return [{"id": "chunk-1", "content": "safe context"}]

	monkeypatch.setattr(orchestrator, "ConflictAwareRetriever", _RecordingRetriever)

	context = _FakeContext(
		{
			"principal": {"role": "privacy-compliance-analyst", "declaredIntent": "compliance_review"},
			"query_text": "Summarise the privacy review emails",
			"action": "summarise",
						"query_embedding": [0.0] * 16,
			"odrl_policy": {
				"@context": "https://www.w3.org/ns/odrl.jsonld",
				"@type": "Set",
				"permission": [
					{
						"uid": "urn:policyaware:permission:test:allow",
						"action": ["summarise"],
						"assignee": "urn:policyaware:role:privacy-compliance-analyst",
						"constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
					}
				],
			},
		}
	)

	generator = orchestrator.orchestrator_function(context)
	first_yield = next(generator)
	assert first_yield["name"] == "GenerateResponseActivity"
	second_yield = generator.send("generated response")
	assert second_yield["name"] == "StoreAuditEventActivity"
	with pytest.raises(StopIteration) as excinfo:
		generator.send({"status": "ok"})

	result = excinfo.value.value

	assert result["status"] == "ok"
	assert retriever_calls["security_filters"] == {}
	assert retriever_calls["top_k"] == 10


def test_build_query_embedding_recomputes_short_vectors(monkeypatch):
	"""Short vectors should be padded to the configured embedding length before use."""
	orchestrator = _load_orchestrator()

	class _FakeSentenceTransformer:
		def __init__(self, model_name):
			self.model_name = model_name

		def encode(self, texts, normalize_embeddings=False):
			assert texts == ["Summarise the privacy review emails"]
			return [[0.1] * 384]

	monkeypatch.setitem(sys.modules, "sentence_transformers", types.SimpleNamespace(SentenceTransformer=_FakeSentenceTransformer))
	monkeypatch.setenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
	result = orchestrator._build_query_embedding("Summarise the privacy review emails", [0.1, 0.2, 0.3])
	assert len(result) == 384
	assert result[0] == 0.1
	assert result[-1] == 0.1


def test_orchestrator_preserves_input_transaction_id():
	"""The orchestration should keep the caller transactionId for audit correlation."""
	orchestrator = _load_orchestrator()
	requested_transaction_id = "tx-eval-123"

	context = _FakeContext(
		{
			"transactionId": requested_transaction_id,
			"principal": {"role": "customer-support-specialist", "declaredIntent": "customer_support"},
			"query_text": "Export the email archive.",
			"action": "export",
			"query_embedding": [0.0] * 16,
			"odrl_policy": {
				"@context": "https://www.w3.org/ns/odrl.jsonld",
				"@type": "Set",
				"permission": [
					{
						"uid": "urn:policyaware:permission:test:deny",
						"action": ["summarise"],
						"constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
					}
				],
			},
		}
	)

	generator = orchestrator.orchestrator_function(context)
	first_yield = next(generator)
	assert first_yield["name"] == "StoreAuditEventActivity"
	audit_payload = first_yield["payload"]
	assert audit_payload["id"] == requested_transaction_id
	assert audit_payload["transactionId"] == requested_transaction_id


def test_context_window_size_medium_sets_top_k_to_20(monkeypatch):
	"""Context window size 'medium' should map retrieval top_k to 20."""
	orchestrator = _load_orchestrator()
	retriever_calls = {}

	class _RecordingRetriever:
		def __init__(self, *args, **kwargs):
			retriever_calls["container_name"] = kwargs.get("container_name")

		def retrieve(self, query_embedding, security_filters, top_k=10):
			retriever_calls["query_embedding"] = query_embedding
			retriever_calls["security_filters"] = security_filters
			retriever_calls["top_k"] = top_k
			return [{"id": "chunk-1", "content": "safe context"}]

	monkeypatch.setattr(orchestrator, "ConflictAwareRetriever", _RecordingRetriever)

	context = _FakeContext(
		{
			"principal": {"role": "privacy-compliance-analyst", "declaredIntent": "compliance_review"},
			"query_text": "Summarise the privacy review emails",
			"action": "summarise",
			"context_window_size": "medium",
			"query_embedding": [0.0] * 16,
			"odrl_policy": {
				"@context": "https://www.w3.org/ns/odrl.jsonld",
				"@type": "Set",
				"permission": [
					{
						"uid": "urn:policyaware:permission:test:allow",
						"action": ["summarise"],
						"assignee": "urn:policyaware:role:privacy-compliance-analyst",
						"constraint": {"leftOperand": "purpose", "operator": "eq", "rightOperand": "compliance_review"},
					}
				],
			},
		}
	)

	generator = orchestrator.orchestrator_function(context)
	first_yield = next(generator)
	assert first_yield["name"] == "GenerateResponseActivity"
	second_yield = generator.send("generated response")
	assert second_yield["name"] == "StoreAuditEventActivity"
	with pytest.raises(StopIteration) as excinfo:
		generator.send({"status": "ok"})

	result = excinfo.value.value

	assert result["status"] == "ok"
	assert retriever_calls["top_k"] == 20


def test_resolve_context_window_size_defaults_and_invalid_values():
	"""Unknown or missing context window size should fall back to small/10."""
	orchestrator = _load_orchestrator()

	default_label, default_top_k = orchestrator._resolve_context_window_size({})
	invalid_label, invalid_top_k = orchestrator._resolve_context_window_size({"context_window_size": "xlarge"})

	assert default_label == "small"
	assert default_top_k == 10
	assert invalid_label == "small"
	assert invalid_top_k == 10