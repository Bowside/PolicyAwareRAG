import json
import importlib
import os
import sys
import types
from unittest import mock


class _FakeHttpResponse:
    """Minimal HTTP response stub used by the function app tests."""

    def __init__(self, body=None, status_code=200):
        self.body = body
        self.status_code = status_code


class _FakeFunctionApp:
    """Minimal Durable Functions app stub used by the tests."""

    def __init__(self, *args, **kwargs):
        self.registered_routes = []

    def orchestration_trigger(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def activity_trigger(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator

    def route(self, *args, **kwargs):
        def decorator(func):
            self.registered_routes.append((args, kwargs, func.__name__))
            return func

        return decorator

    def durable_client_input(self, *args, **kwargs):
        def decorator(func):
            return func

        return decorator


class _FakeDurableClient:
    """Fake durable client that records the latest orchestration payload."""

    def __init__(self):
        self.started = None

    async def start_new(self, name, instance_id, input_data):
        self.started = (name, instance_id, input_data)
        return "instance-123"

    def create_check_status_response(self, req, instance_id):
        return {"instanceId": instance_id, "method": req.method}


class _FakeRequest:
    """Fake HTTP request wrapper for start-orchestration tests."""

    def __init__(self, payload, method="POST"):
        self._payload = payload
        self.method = method

    def get_json(self):
        return self._payload


def _install_azure_stubs():
    """Install lightweight Azure SDK stubs for isolated unit tests."""
    azure_pkg = types.ModuleType("azure")
    azure_pkg.__path__ = []

    numpy_mod = types.ModuleType("numpy")

    class _FakeArray(list):
        @property
        def size(self):
            return len(self)

    numpy_mod.ndarray = _FakeArray

    class _FakeLinalg:
        @staticmethod
        def norm(values):
            return sum(float(value) * float(value) for value in values) ** 0.5

    def _array(values, dtype=float):
        return _FakeArray(float(value) for value in values)

    def _dot(left, right):
        return sum(float(a) * float(b) for a, b in zip(left, right))

    numpy_mod.array = _array
    numpy_mod.dot = _dot
    numpy_mod.linalg = _FakeLinalg()

    identity_mod = types.ModuleType("azure.identity")

    class _FakeDefaultAzureCredential:
        pass

    identity_mod.DefaultAzureCredential = _FakeDefaultAzureCredential

    cosmos_mod = types.ModuleType("azure.cosmos")

    class _FakeContainer:
        def __init__(self):
            self.created_items = []
            self.upserted_items = []

        def query_items(self, *ia, **ik):
            return []

        def create_item(self, *, body, **ck):
            self.created_items.append(body)
            return body

        def upsert_item(self, *, body, **ck):
            self.upserted_items.append(body)
            return body

    class _FakeDatabaseClient:
        def __init__(self):
            self.container = _FakeContainer()

        def get_container_client(self, *args, **kwargs):
            return self.container

    class _FakeCosmosClient:
        _last_database_client = _FakeDatabaseClient()

        def __init__(self, *args, **kwargs):
            self.database_client = self._last_database_client

        def get_database_client(self, *args, **kwargs):
            return self.database_client

    cosmos_mod.CosmosClient = _FakeCosmosClient

    functions_mod = types.ModuleType("azure.functions")
    functions_mod.AuthLevel = types.SimpleNamespace(ANONYMOUS="anonymous")
    functions_mod.HttpRequest = _FakeRequest
    functions_mod.HttpResponse = _FakeHttpResponse

    durable_mod = types.ModuleType("azure.durable_functions")
    durable_mod.DFApp = _FakeFunctionApp
    durable_mod.DurableOrchestrationContext = object
    durable_mod.DurableOrchestrationClient = _FakeDurableClient
    durable_mod.Orchestrator = types.SimpleNamespace(create=lambda func: func)

    sys.modules["azure"] = azure_pkg
    sys.modules["numpy"] = numpy_mod
    sys.modules["azure.identity"] = identity_mod
    sys.modules["azure.cosmos"] = cosmos_mod
    sys.modules["azure.functions"] = functions_mod
    sys.modules["azure.durable_functions"] = durable_mod


def test_start_orchestration_returns_check_status_response():
    """Verify the start endpoint returns the durable status response."""
    _install_azure_stubs()
    os.environ["COSMOS_DB_ENDPOINT"] = "https://example-cosmos.documents.azure.com:443/"
    os.environ["COSMOS_DB_DATABASE"] = "policy_rag_db"
    sys.modules.pop("function_app", None)
    function_app = importlib.import_module("function_app")

    client = _FakeDurableClient()
    request = _FakeRequest({"principal": {"role": "privacy-analyst"}, "cosmos_collection": "VectorDatabase"})

    response = importlib.import_module("asyncio").run(function_app.start_orchestration(request, client))

    assert response == {"instanceId": "instance-123", "method": "POST"}
    assert client.started[0] == "orchestrator"
    assert client.started[2]["cosmos_endpoint"] == "https://example-cosmos.documents.azure.com:443/"
    assert client.started[2]["database"] == "policy_rag_db"


def test_orchestrator_defaults_missing_collection_to_sample_store():
    """Verify the orchestrator falls back to the sample Cosmos container."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    captured = {}

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            captured["cosmos_endpoint"] = cosmos_endpoint
            captured["database_name"] = database_name
            captured["cosmos_collection"] = cosmos_collection

        def retrieve(self, query_embedding, filters, top_k=10):
            return []

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                "odrl_policy": {"permission": [{"uid": "rule-1", "action": ["summarise"]}]},
                "query_text": "Summarise the approved content.",
                "query_embedding": list(range(16)),
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            first_yield = next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            if 'result' not in locals():
                result = stop.value

    assert first_yield == {"status": "ok"}

    assert captured["cosmos_collection"] == "EnronEmailVectorStore"


def test_orchestrator_forwards_security_filters_to_retriever():
    """Verify policy-derived security filters reach the retriever."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    captured = {}

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            captured["cosmos_endpoint"] = cosmos_endpoint
            captured["database_name"] = database_name
            captured["cosmos_collection"] = cosmos_collection

        def retrieve(self, query_embedding, filters, top_k=10):
            captured["filters"] = filters
            return []

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                    "odrl_policy": {
                        "uid": "urn:policyaware:policy:privacy-compliance-analyst",
                        "permission": [
                            {
                                "uid": "urn:policyaware:permission:privacy-compliance-analyst:compliance-review",
                                "target": "urn:policyaware:asset:pii-rag-corpus",
                                "action": ["summarise"],
                                "assignee": "urn:policyaware:role:privacy-compliance-analyst",
                                "constraint": {
                                    "leftOperand": "purpose",
                                    "operator": "eq",
                                    "rightOperand": "compliance_review",
                                },
                            }
                        ],
                    },
                "query_text": "Summarise the approved content.",
                "query_embedding": list(range(16)),
                "security_filters": {"classification": "confidential", "disallow": False},
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            first_yield = next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            result = stop.value

    assert first_yield == {"status": "ok"}
    assert captured["filters"] == {
        "policyUid": "privacy-compliance-analyst",
        "policyRole": "privacy-compliance-analyst",
        "policyTarget": "pii-rag-corpus",
        "policyAction": "summarise",
        "policyPurpose": "compliance_review",
    }
    assert result["status"] == "ok"


def test_count_query_does_not_build_embedding():
    """Verify count queries skip embedding generation and return counts."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            self.cosmos_endpoint = cosmos_endpoint
            self.database_name = database_name
            self.cosmos_collection = cosmos_collection

        def count_by_sender(self, sender, security_filters=None):
            return 7

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                "odrl_policy": {"permission": [{"uid": "rule-1", "action": ["summarise"]}]},
                "query_text": "How many emails did Fran Fagan send?",
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator, "_build_query_embedding", side_effect=AssertionError("embedding build should be skipped")
    ), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            first_yield = next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            result = stop.value

    assert first_yield == {"status": "ok"}
    assert result["status"] == "ok"
    assert result["outcomeType"] == "count_result"
    assert result["count"] == 7


def test_orchestrator_counts_sender_queries_without_llm():
    """Verify count queries resolve without calling the LLM activity."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    captured = {}

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            captured["cosmos_endpoint"] = cosmos_endpoint
            captured["database_name"] = database_name
            captured["cosmos_collection"] = cosmos_collection

        def count_by_sender(self, sender_query, security_filters=None):
            captured["sender_query"] = sender_query
            captured["security_filters"] = security_filters
            return 3

        def retrieve(self, query_embedding, filters, top_k=10):
            raise AssertionError("retrieve should not be called for count queries")

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "CEO", "declaredIntent": "business_review"},
                "odrl_policy": {"permission": [{"uid": "rule-1", "action": ["summarise"]}]},
                "query_text": "How many emails did Fran Fagan send?",
                "query_embedding": list(range(16)),
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            first_yield = next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            if 'result' not in locals():
                result = stop.value

    assert first_yield == {"status": "ok"}
    assert captured["sender_query"] == "Fran Fagan"
    assert captured["cosmos_collection"] == "EnronEmailVectorStore"
    assert result["status"] == "ok"
    assert result["outcomeType"] == "count_result"
    assert result["count"] == 3
    assert result["result"] == "Fran Fagan sent 3 emails."


def test_orchestrator_counts_sender_query_with_typo_variant():
    """Verify common sender-name typos still resolve to the count path."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    captured = {}

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            captured["cosmos_collection"] = cosmos_collection

        def count_by_sender(self, sender_query, security_filters=None):
            captured["sender_query"] = sender_query
            captured["security_filters"] = security_filters
            return 9

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "privacy-compliance-analyst", "declaredIntent": "compliance_review"},
                "odrl_policy": {
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
                },
                "query_text": "How many emails did Frans Fagan send?",
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            result = stop.value

    assert captured["sender_query"] == "Frans Fagan"
    assert result["outcomeType"] == "count_result"
    assert result["count"] == 9


def test_orchestrator_uses_multi_agent_graph_to_deny_disallowed_chunks():
    """Verify disallowed chunks are denied before generation starts."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    called_activities = []

    class _FakeRetriever:
        def __init__(self, cosmos_endpoint, database_name, cosmos_collection):
            self.cosmos_endpoint = cosmos_endpoint
            self.database_name = database_name
            self.cosmos_collection = cosmos_collection

        def retrieve(self, query_embedding, filters, top_k=10):
            return [{"id": "chunk-1", "securityMetadata": {"disallow": True}, "content": "restricted content"}]

    class _FakeContext:
        def get_input(self):
            return {
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                "odrl_policy": {"permission": [{"uid": "rule-1", "action": ["summarise"]}]},
                "query_text": "Summarise the approved content.",
                "query_embedding": list(range(16)),
                "action": "summarise",
                "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
                "database": "policy_rag_db",
            }

        def call_activity(self, *args, **kwargs):
            called_activities.append(args[0])
            if args and args[0] == "StoreAuditEventActivity":
                return {"status": "ok"}
            raise AssertionError(f"Unexpected activity call: {args!r} {kwargs!r}")

    with mock.patch.object(orchestrator, "ConflictAwareRetriever", _FakeRetriever), mock.patch.object(
        orchestrator.PolicyPurposeValidator, "evaluate", return_value=(True, {"satisfied": True, "matchedRules": ["rule-1"]})
    ):
        generator = orchestrator.orchestrator_function(_FakeContext())
        try:
            first_yield = next(generator)
            result = generator.send({"status": "ok"})
        except StopIteration as stop:
            result = stop.value

    assert first_yield == {"status": "ok"}
    assert result["status"] == "denied"
    assert "GenerateResponseActivity" not in called_activities


def test_start_orchestration_rejects_invalid_json():
    """Verify malformed JSON requests are rejected with HTTP 400."""
    _install_azure_stubs()
    sys.modules.pop("function_app", None)
    function_app = importlib.import_module("function_app")

    class _BadRequest(_FakeRequest):
        def get_json(self):
            raise ValueError("bad json")

    response = importlib.import_module("asyncio").run(function_app.start_orchestration(_BadRequest(None), _FakeDurableClient()))

    assert response.status_code == 400


def test_generate_response_activity_uses_ai_foundry_chat_completion():
    """Verify the response activity calls AI Foundry with the expected prompt."""
    _install_azure_stubs()
    os.environ["AI_FOUNDRY_Endpoint"] = "https://example-foundry.services.ai.azure.com/models"
    os.environ["AI_FOUNDRY_KEY"] = "test-key"
    os.environ["AI_FOUNDRY_MODEL"] = "test-model"
    sys.modules.pop("activities", None)
    activities = importlib.import_module("activities")

    class _FakeUrlResponse:
        def __init__(self, payload):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return self._payload

    captured = {}

    def _fake_urlopen(request, timeout=60):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.data.decode("utf-8"))
        response_body = json.dumps(
            {"choices": [{"message": {"content": "Approved answer"}}]}
        ).encode("utf-8")
        return _FakeUrlResponse(response_body)

    with mock.patch.object(activities.urllib.request, "urlopen", side_effect=_fake_urlopen):
        result = activities.GenerateResponseActivity(
            {
                "query_text": "What is the policy outcome?",
                "retrieved": [{"id": "chunk-1", "content": "Allowed information only."}],
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                "policy_evaluation": {"satisfied": True, "matchedRules": ["rule-1"]},
                "action": "summarise",
            }
        )

    assert result == "Approved answer"
    assert captured["url"].endswith("/chat/completions?api-version=2024-05-01-preview")
    assert captured["body"]["model"] == "test-model"
    assert "What is the policy outcome?" in captured["body"]["messages"][1]["content"]


def test_generate_response_activity_includes_body_field_from_retrieved_documents():
    """Verify retrieved email bodies are included in the generation prompt."""
    _install_azure_stubs()
    os.environ["AI_FOUNDRY_Endpoint"] = "https://example-foundry.services.ai.azure.com/models"
    os.environ["AI_FOUNDRY_KEY"] = "test-key"
    os.environ["AI_FOUNDRY_MODEL"] = "test-model"
    sys.modules.pop("activities", None)
    activities = importlib.import_module("activities")

    class _FakeUrlResponse:
        def __init__(self, payload):
            self._payload = payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return self._payload

    captured = {}

    def _fake_urlopen(request, timeout=60):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        response_body = json.dumps({"choices": [{"message": {"content": "Approved answer"}}]}).encode("utf-8")
        return _FakeUrlResponse(response_body)

    retrieved = [
        {
            "subject": "FW: final ratings",
            "from": "lynn.blair@enron.com",
            "to": "sheila.nacey@enron.com",
            "date": "Mon, 30 Jul 2001 07:05:23 -0700",
            "body": "FYI. Thanks. Lynn",
            "similarity_score": 0.4189439595463752,
        }
    ]

    with mock.patch.object(activities.urllib.request, "urlopen", side_effect=_fake_urlopen):
        result = activities.GenerateResponseActivity(
            {
                "query_text": "Summarise the relevant privacy review emails",
                "retrieved": retrieved,
                "principal": {"role": "privacy-analyst", "declaredIntent": "compliance_review"},
                "policy_evaluation": {"satisfied": True, "matchedRules": ["rule-1"]},
                "action": "summarise",
            }
        )

    assert result == "Approved answer"
    prompt = captured["body"]["messages"][1]["content"]
    assert "FYI. Thanks. Lynn" in prompt
    assert "from: lynn.blair@enron.com" in prompt
    assert "subject: FW: final ratings" in prompt


def test_build_audit_event_includes_request_policy_and_outcome():
    """Verify audit events capture request, policy, and outcome data."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    audit_event = orchestrator.build_audit_event(
        transaction_id="11111111-1111-1111-1111-111111111111",
        start_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 0),
        end_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 5),
        duration_seconds=5.0,
        principal={"userId": "user-1", "role": "privacy-analyst", "declaredIntent": "compliance_review"},
        odrl_policy={"uid": "policy:privacy-analyst"},
        query_text="Summarise the approved content.",
        query_embedding=[0.1, 0.2, 0.3],
        action="summarise",
        cosmos_collection="EnronEmailVectorStore",
        database_name="policy_rag_db",
        retrieved=[{"id": "chunk-1", "content": "Allowed information only."}],
        eval_detail={"matchedRules": ["policy:privacy-analyst"], "satisfied": True, "reasoning": ["allowed"]},
        allowed=True,
        guard={"status": "Pass"},
        enforcement_action_type="Allow",
        final_payload={"status": "ok", "result": "Approved answer"},
    )

    assert audit_event["id"] == "11111111-1111-1111-1111-111111111111"
    assert audit_event["transactionId"] == "11111111-1111-1111-1111-111111111111"
    assert audit_event["startTime"] == "2026-01-01T12:00:00"
    assert audit_event["endTime"] == "2026-01-01T12:00:05"
    assert audit_event["durationSeconds"] == 5.0
    assert audit_event["request"]["cosmosCollectionId"] == "EnronEmailVectorStore"
    assert audit_event["odrlPolicy"]["uid"] == "policy:privacy-analyst"
    assert audit_event["policyEvaluation"]["ruleType"] == "Permission"
    assert audit_event["policyEvaluation"]["constraintSatisfaction"] is True
    assert audit_event["policyEvaluation"]["reasoningTrail"] == "allowed"
    assert audit_event["enforcementAction"]["complianceGuardStatus"] == "Passed"
    assert audit_event["outcome"]["result"] == "Approved answer"


def test_build_audit_event_preserves_no_results_outcome_type():
    """Verify no-results outcomes are preserved in the audit payload."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    audit_event = orchestrator.build_audit_event(
        transaction_id="33333333-3333-3333-3333-333333333333",
        start_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 0),
        end_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 2),
        duration_seconds=2.0,
        principal={"userId": "user-3", "role": "CEO", "declaredIntent": "business_review"},
        odrl_policy={"uid": "policy:full-access"},
        query_text="Find any matching content.",
        query_embedding=[0.4, 0.5, 0.6],
        action="summarise",
        cosmos_collection="EnronEmailVectorStore",
        database_name="policy_rag_db",
        retrieved=[],
        eval_detail={"matchedRules": ["policy:full-access"], "satisfied": True, "reasoning": ["allowed"]},
        allowed=True,
        guard={"status": "Pass"},
        enforcement_action_type="Allow",
        final_payload={
            "status": "ok",
            "outcomeType": "no_results",
            "result": "No relevant context was retrieved for this request.",
        },
    )

    assert audit_event["outcome"]["outcomeType"] == "no_results"
    assert audit_event["outcome"]["status"] == "ok"
    assert audit_event["enforcementAction"]["complianceGuardStatus"] == "Passed"


def test_build_audit_event_includes_timing_fields():
    """Verify audit events include start, end, and duration timestamps."""
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    audit_event = orchestrator.build_audit_event(
        transaction_id="44444444-4444-4444-4444-444444444444",
        start_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 0),
        end_time=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 3),
        duration_seconds=3.0,
        principal={"userId": "user-4", "role": "CEO", "declaredIntent": "business_review"},
        odrl_policy={"uid": "policy:full-access"},
        query_text="Find any matching content.",
        query_embedding=[0.1, 0.2, 0.3],
        action="summarise",
        cosmos_collection="EnronEmailVectorStore",
        database_name="policy_rag_db",
        retrieved=[],
        eval_detail={"matchedRules": ["policy:full-access"], "satisfied": True, "reasoning": ["allowed"]},
        allowed=True,
        guard={"status": "Pass"},
        enforcement_action_type="Allow",
        final_payload={"status": "ok", "outcomeType": "no_results", "result": "No relevant context was retrieved for this request."},
    )

    assert audit_event["timestamp"] == "2026-01-01T12:00:00"
    assert audit_event["startTime"] == "2026-01-01T12:00:00"
    assert audit_event["endTime"] == "2026-01-01T12:00:03"
    assert audit_event["durationSeconds"] == 3.0


def test_store_audit_event_activity_upserts_with_transaction_id_as_item_id():
    """Verify audit events are upserted with the transaction ID as the item ID."""
    _install_azure_stubs()
    os.environ["COSMOS_KEY"] = "test-cosmos-key"
    sys.modules.pop("activities", None)
    activities = importlib.import_module("activities")

    result = activities.StoreAuditEventActivity(
        {
            "transactionId": "22222222-2222-2222-2222-222222222222",
            "cosmos_endpoint": "https://example-cosmos.documents.azure.com:443/",
            "database": "policy_rag_db",
            "principal": {"userId": "user-2", "role": "CEO", "declaredIntent": "disciplinary_investigation"},
            "policyEvaluation": {"matchedPolicyUid": "policy:full-access"},
            "enforcementAction": {"actionType": "Allow", "filteredNodesCount": 1, "complianceGuardStatus": "Passed"},
            "outcome": {"status": "ok", "result": "Approved answer"},
        }
    )

    assert result == {"status": "ok"}
    container = activities.CosmosClient._last_database_client.get_container_client("AuditStorage")
    assert container.upserted_items[0]["id"] == "22222222-2222-2222-2222-222222222222"
