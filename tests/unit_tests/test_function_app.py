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

# Rest of tests unchanged — copied from original tests/test_function_app.py
