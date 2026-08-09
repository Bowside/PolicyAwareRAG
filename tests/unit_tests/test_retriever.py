import importlib
import sys
import types


class _FakeContainer:
    def __init__(self, items):
        self.items = items
        self.queries = []

    def query_items(self, *, query, parameters, enable_cross_partition_query):
        self.queries.append(
            {
                "query": query,
                "parameters": parameters,
                "enable_cross_partition_query": enable_cross_partition_query,
            }
        )
        return self.items


class _FakeDatabaseClient:
    def __init__(self, container):
        self.container = container

    def get_container_client(self, name):
        self.container_name = name
        self.container.container_name = name
        return self.container


class _FakeCosmosClient:
    last_instance = None

    def __init__(self, *args, **kwargs):
        self.container = _FakeContainer(
            [
                {"id": "chunk-1", "subject": "Quarterly review", "body": "Policy-safe context"},
                {"id": "chunk-2", "subject": "Second review", "body": "Another context chunk"},
            ]
        )
        self.database_client = _FakeDatabaseClient(self.container)
        _FakeCosmosClient.last_instance = self

    def get_database_client(self, name):
        self.database_name = name
        return self.database_client



def test_retrieve_returns_cosmos_rows(monkeypatch, caplog):
    fake_cosmos = types.ModuleType("azure.cosmos")
    fake_cosmos.CosmosClient = _FakeCosmosClient
    monkeypatch.setitem(sys.modules, "azure.cosmos", fake_cosmos)
    monkeypatch.setenv("COSMOSDB_ENDPOINT", "https://example-cosmos.documents.azure.com:443/")
    monkeypatch.setenv("COSMOSDB_DATABASE", "policy_rag_db")
    monkeypatch.setenv("COSMOSDB_KEY", "fake-key")
    monkeypatch.setenv("COSMOS_ENRON_COLLECTION", "EnronEmailVectorStore")

    sys.modules.pop("retriever", None)
    retriever = importlib.import_module("retriever")

    with caplog.at_level("INFO"):
        instance = retriever.ConflictAwareRetriever()
        results = instance.retrieve([0.1] * 16, {"role": "privacy-analyst"}, top_k=2)

    assert [row["id"] for row in results] == ["chunk-1", "chunk-2"]
    assert _FakeCosmosClient.last_instance.database_name == "policy_rag_db"
    assert _FakeCosmosClient.last_instance.database_client.container.container_name == "EnronEmailVectorStore"
    assert _FakeCosmosClient.last_instance.container.queries
    assert "VectorDistance" in _FakeCosmosClient.last_instance.container.queries[0]["query"]
    assert "Cosmos vector query returned 2 item(s)" in caplog.text
