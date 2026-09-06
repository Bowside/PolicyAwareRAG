# Performance Evaluations

`run_evaluations.py` sends the defined evaluation cases to the live PolicyAwareRAG Function App and writes a JSON result file containing outcomes, latency, token estimates, audit-step metrics, and optional RAGAS scores.

## Prerequisites

From the repository root, create or activate the virtual environment and install the project dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create or update the root `.env` file with the evaluation target:

```env
FUNCTION_APP_URL=https://<your-function-app>.azurewebsites.net/api/rag
FUNCTION_APP_KEY=<your-function-app-key>
```

To retrieve audit records and per-step metrics, also set:

```env
COSMOSDB_ENDPOINT=https://<your-cosmos-account>.documents.azure.com:443/
COSMOSDB_KEY=<your-cosmos-key>
COSMOSDB_DATABASE=policy_rag_db
COSMOSDB_AUDIT_CONTAINER=AuditStorage
```

The `.env` file is ignored by Git and must not be committed.

## Run the full evaluation suite

```powershell
python tests/performance_evaluation/run_evaluations.py
```

By default, all 120 evaluation cases run with a maximum of 4 concurrent threads.

## Control threads and test count

Use `--max-threads` to control concurrent requests and `--max-tests` to sample a
specific number of cases across the policy case types:

```powershell
python tests/performance_evaluation/run_evaluations.py --max-threads 8 --max-tests 25
```

In this example, 25 cases are sampled across the 12 case types and run with at
most 8 concurrent workers. Both values must be at least 1. If `--max-tests` is
omitted, all cases run.

Use `--seed` to reproduce the same sample later:

```powershell
python tests/performance_evaluation/run_evaluations.py --max-tests 25 --seed 42
```

Each case type has 10 variants covering the ODRL roles and purposes for
observer, support, privacy, administrator, and prohibited-export scenarios.

You can view all options with:

```powershell
python tests/performance_evaluation/run_evaluations.py --help
```

## Results

Results are saved beside the script as:

```text
tests/performance_evaluation/evaluation_results_<timestamp>.json
```

The console reports the output path and the pass rate after the run completes. Evaluation result files are ignored by Git.

Each result includes human-review fields at the top level:

- `original_prompt`: the exact prompt sent to the Function App.
- `request_payload`: the complete JSON request, including role, purpose, and action.
- `response_text`: the raw response body returned by the Function App.
- `response`: the parsed JSON response when the body is valid JSON.

This makes it possible to review the original prompt beside the generated answer
or error response without reconstructing the request from the metadata.
