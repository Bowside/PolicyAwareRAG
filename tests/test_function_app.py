import json
import importlib
import os
import sys
import types
from unittest import mock


class _FakeHttpResponse:
    def __init__(self, body=None, status_code=200):
        self.body = body
        self.status_code = status_code


class _FakeFunctionApp:
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
    def __init__(self):
        self.started = None

    async def start_new(self, name, instance_id, input_data):
        self.started = (name, instance_id, input_data)
        return "instance-123"

    def create_check_status_response(self, req, instance_id):
        return {"instanceId": instance_id, "method": req.method}


class _FakeRequest:
    def __init__(self, payload, method="POST"):
        self._payload = payload
        self.method = method

    def get_json(self):
        return self._payload


def _install_azure_stubs():
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


def test_start_orchestration_rejects_invalid_json():
    _install_azure_stubs()
    sys.modules.pop("function_app", None)
    function_app = importlib.import_module("function_app")

    class _BadRequest(_FakeRequest):
        def get_json(self):
            raise ValueError("bad json")

    response = importlib.import_module("asyncio").run(function_app.start_orchestration(_BadRequest(None), _FakeDurableClient()))

    assert response.status_code == 400


def test_generate_response_activity_uses_ai_foundry_chat_completion():
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


def test_build_audit_event_includes_request_policy_and_outcome():
    _install_azure_stubs()
    sys.modules.pop("orchestrator", None)
    orchestrator = importlib.import_module("orchestrator")

    audit_event = orchestrator.build_audit_event(
        transaction_id="11111111-1111-1111-1111-111111111111",
        timestamp=importlib.import_module("datetime").datetime(2026, 1, 1, 12, 0, 0),
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
    assert audit_event["request"]["cosmosCollectionId"] == "EnronEmailVectorStore"
    assert audit_event["odrlPolicy"]["uid"] == "policy:privacy-analyst"
    assert audit_event["policyEvaluation"]["ruleType"] == "Permission"
    assert audit_event["policyEvaluation"]["constraintSatisfaction"] is True
    assert audit_event["policyEvaluation"]["reasoningTrail"] == "allowed"
    assert audit_event["enforcementAction"]["complianceGuardStatus"] == "Passed"
    assert audit_event["outcome"]["result"] == "Approved answer"


def test_store_audit_event_activity_upserts_with_transaction_id_as_item_id():
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
