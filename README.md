# PolicyAwareRAG

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
FOUNDRY_API_KEY
FOUNDRY_ENDPOINT
FOUNDRY_CHAT_MODEL
FOUNDRY_TEMPERATURE
COSMOSDB_ENDPOINT
COSMOSDB_KEY
COSMOSDB_DATABASE
COSMOSDB_COLLECTION
LOCAL_EMBEDDING_MODEL
HUGGINGFACE_TOKEN
```

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

The health endpoint is available at `GET http://localhost:7071/api/health`.

Set `ENABLE_EVALUATION_DETAILS=true` only when a request must include
`"includeEvaluationDetails": true` and return the pre-guardrail answer.

## Tests

Run the unit tests from the repository root:

```powershell
python -m pytest -q tests/unit_tests
```

For the evaluation runner and analysis notebook, see
[tests/performance_evaluation/README.md](tests/performance_evaluation/README.md).
