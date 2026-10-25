# PolicyAwareRAG

PolicyAwareRAG is an Azure Functions HTTP application that combines Cosmos DB
vector retrieval with Microsoft Foundry answer generation. ODRL policies are
evaluated before retrieval, retrieved documents are filtered by their security
metadata, and the generated answer passes through deterministic and, where
required, semantic spokesperson checks before it is returned.

## Run locally

Create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Copy `local.settings.sample.json` to `local.settings.json` and set the values
listed below. The local embedding model also requires a Hugging Face read token
after accepting the model's usage terms.

```text
AzureWebJobsStorage
FUNCTIONS_WORKER_RUNTIME
FOUNDRY_API_KEY
FOUNDRY_ENDPOINT
FOUNDRY_CHAT_MODEL
FOUNDRY_EMBEDDING_MODEL
FOUNDRY_TEMPERATURE
COSMOSDB_ENDPOINT
COSMOSDB_KEY
COSMOSDB_DATABASE
COSMOSDB_COLLECTION
LOCAL_EMBEDDING_MODEL
```

`HUGGINGFACE_TOKEN` is required when the configured local embedding model is a
Hugging Face model, such as the default `google/embeddinggemma-300m`. The
sample settings file also enables `ENABLE_EVALUATION_DETAILS`; leave this
disabled unless evaluation needs the unguarded base answer returned alongside
the protected answer.

Start the Azure Functions host from the repository root:

```powershell
func start
```

Send a request to the RAG endpoint:

```powershell
curl.exe -X POST http://localhost:7071/api/rag `
  -H "Content-Type: application/json" `
  -d '{"question":"Who was involved in the California energy trading discussions?","userRoles":["business-observer"],"purpose":"metadata_review","action":"retrieve"}'
```

The request must contain a non-empty `question` and at least one recognized
policy role in `userRoles` (the legacy `roles` field is also accepted). The
optional fields are `purpose`, `action`, `userId`, `correlationId`, and
`includeEvaluationDetails`. Actions include `retrieve`, `summarise`,
`summarize`, `audit`, `redact`, and `export`; the active role policy must permit
the selected action and purpose.

Successful responses contain `question`, `answer`, `sources`, `userRoles`,
`purpose`, and `correlationId`. Invalid JSON or missing questions return `400`;
policy denials return `403` with `policyDenied: true`; unexpected failures
return `500`. The endpoint is configured as anonymous locally, although a
deployed Function App may be protected by its hosting configuration.

The health endpoint is available at `GET http://localhost:7071/api/health`.

Set `ENABLE_EVALUATION_DETAILS=true` only when a request must include
`"includeEvaluationDetails": true` and return the pre-guardrail answer as
`evaluationDetails.baseAnswer`. Audit records are written to the
`AuditStorage` Cosmos container when Cosmos credentials are configured; audit
failures do not fail the HTTP request.

By default retrieval uses hybrid vector and keyword candidates, then lexical
reranking. Set `RAG_RETRIEVAL_MODE=vector` to disable keyword retrieval and
`RAG_RERANKING_MODE=vector` to skip lexical reranking. The candidate limit is
controlled by `RAG_VECTOR_CANDIDATES` and defaults to `200`.

## Tests

Run the unit tests from the repository root:

```powershell
python -m pytest -q tests/unit_tests
```

For the evaluation runner and analysis notebook, see
[tests/performance_evaluation/README.md](tests/performance_evaluation/README.md).
