# Performance evaluations

This folder contains the evaluation runner, result files, reference answers,
figures, and analysis notebook.

## Prerequisites

From the repository root, activate the virtual environment and install the
project dependencies:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create or update the root `.env` file with the Function App target:

```env
FUNCTION_APP_URL=https://<your-function-app>.azurewebsites.net/api/rag
FUNCTION_APP_KEY=<your-function-app-key>

# Optional: return the pre-guardrail answer for evaluation details.
ENABLE_EVALUATION_DETAILS=true
```

`ENABLE_EVALUATION_DETAILS` is optional. It must be enabled on the Function App
and in the evaluator when base and final answers are both required.

The deployed Function App must also have `LOCAL_EMBEDDING_MODEL` and
`HUGGINGFACE_TOKEN` configured. Do not commit the token to the repository.

To retrieve audit records and per-step metrics, also set:

```env
COSMOSDB_ENDPOINT=https://<your-cosmos-account>.documents.azure.com:443/
COSMOSDB_KEY=<your-cosmos-key>
COSMOSDB_DATABASE=policy_rag_db
COSMOSDB_AUDIT_CONTAINER=AuditStorage
```

The evaluator also uses `COSMOSDB_ENDPOINT`, `COSMOSDB_KEY`,
`COSMOSDB_DATABASE`, and `COSMOSDB_COLLECTION` to resolve audited source IDs to
document bodies.

The `.env` file is ignored by Git and must not be committed.

## Run the full evaluation suite

```powershell
python tests/performance_evaluation/run_evaluations.py
```

By default, all evaluation cases run with two concurrent threads and a
one-second interval between request starts.

## Control threads and test count

Use `--max-threads` to control concurrent requests and `--max-tests` to sample a
specific number of cases across the policy case types:

```powershell
python tests/performance_evaluation/run_evaluations.py --max-threads 8 --max-tests 25
```

In this example, 25 cases are sampled across the standard case types and run
with at most 8 concurrent workers. Both values must be at least 1. When
`--max-tests` is supplied, the sample reserves `ceil(max-tests * 0.10)` cases
for the red-team suite, with at least one red-team case. If `--max-tests` is
omitted, all cases run.

Use `--seed` to reproduce the same sample later:

```powershell
python tests/performance_evaluation/run_evaluations.py --max-tests 25 --seed 42
```

To protect a low-throughput Cosmos account, reduce concurrency and pace request
starts. The evaluator defaults to a one-second interval between requests. For a
run that measures response behavior without the evaluator's extra audit and
source-context reads, also use `--skip-cosmos-enrichment`:

```powershell
python tests/performance_evaluation/run_evaluations.py --max-threads 2 --max-tests 25 --request-interval 2 --skip-cosmos-enrichment
```

The Function App still performs its normal vector retrieval and audit write for
each request. To reduce retrieval RU further, set `RAG_RETRIEVAL_MODE=vector`
and lower `RAG_VECTOR_CANDIDATES` on the Function App for the evaluation window.

You can view all options with:

```powershell
python tests/performance_evaluation/run_evaluations.py --help
```

## Output

Results are saved beside the script as:

```text
tests/performance_evaluation/evaluation_results_<timestamp>.json
```

The console reports the output path and the pass rate after the run completes. Evaluation result files are ignored by Git.

Each result includes the request, response, outcome, latency, token, and audit
fields. When Cosmos enrichment is enabled, it also includes retrieved document
context and named pipeline-step metrics. Token counts are estimates based on
four characters per token, not provider billing values.

## Human-curated references

Reference-dependent RAGAS metrics (`context_precision` and `context_recall`) run only for questions with curated answers. Add exact question-to-answer mappings to:

```text
tests/performance_evaluation/reference_answers.json
```

Example:

```json
{
	"Review the metadata for the customer account correspondence.": "A concise, human-reviewed answer grounded in the retrieved emails."
}
```

Do not use model-generated answers as references.

## Analysis notebook

Open `evaluation_analysis.ipynb` after generating a results file. It reports pass rate, request and step latency, evaluation-stage token usage, and RAGAS scores. It exports PNG and SVG figures to:

```text
tests/performance_evaluation/figures/
```
