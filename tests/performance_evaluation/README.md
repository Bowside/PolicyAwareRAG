# Performance Evaluations

`run_evaluations.py` sends the defined evaluation cases to the live PolicyAwareRAG Function App and writes a JSON result file containing outcomes, latency, token estimates, resolved evaluation context, audit-step metrics, and optional RAGAS scores.

The application retrieves up to 20 vector candidates, applies policy filtering, reranks them by body and subject query-term overlap, and sends at most 8 documents to generation. Sender addresses are excluded from lexical scoring. Set `RAG_RERANKING_MODE=vector` to preserve vector-search order for a with/without-reranking ablation. The answer prompt uses source-labeled evidence and requires citations for factual claims. The vector corpus uses `google/embeddinggemma-300m`; its source emails are normalized and split into 1,200-character chunks with 200-character overlap before embedding. Security metadata is assigned deterministically with `keyword_and_pii_rules_v1` before chunking and copied to every chunk from the source email.

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

# Set this on the Function App and evaluator for base-versus-final RAGAS scores.
ENABLE_EVALUATION_DETAILS=true
```

`ENABLE_EVALUATION_DETAILS` is optional and should be enabled only for controlled evaluation runs. When enabled, requests that explicitly include evaluation details return the pre-guardrail answer in addition to the final guarded answer. Normal API responses remain unchanged when it is disabled.

The deployed Function App must also have `LOCAL_EMBEDDING_MODEL=google/embeddinggemma-300m` and `HUGGINGFACE_TOKEN` configured. To obtain the model, create or sign in to a Hugging Face account, accept Google's applicable usage terms/license on the `google/embeddinggemma-300m` model page, and create a read access token. Do not commit the token to the repository.

To retrieve audit records and per-step metrics, also set:

```env
COSMOSDB_ENDPOINT=https://<your-cosmos-account>.documents.azure.com:443/
COSMOSDB_KEY=<your-cosmos-key>
COSMOSDB_DATABASE=policy_rag_db
COSMOSDB_AUDIT_CONTAINER=AuditStorage
```

The evaluator also uses `COSMOSDB_ENDPOINT`, `COSMOSDB_KEY`, `COSMOSDB_DATABASE`, and `COSMOSDB_COLLECTION` to resolve audited source IDs to document bodies. RAGAS is evaluated against those document bodies, not source IDs.

The `.env` file is ignored by Git and must not be committed.

## Run the full evaluation suite

```powershell
python tests/performance_evaluation/run_evaluations.py
```

By default, all 430 evaluation cases run with a maximum of 4 concurrent threads,
including 10 deterministic red-team cases.

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

The standard suite has 20 variants for each of 21 policy case types covering
observer, support, privacy, administrator, and prohibited-export scenarios.
The red-team suite covers prompt injection, privilege escalation, role spoofing,
missing roles, purpose mismatches, and action mismatches.

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
- `evaluation_contexts`: the retrieved document bodies used as RAGAS contexts when audit records are available.
- `base_answer`: the pre-guardrail answer when evaluation details are enabled; otherwise it equals the final answer.
- `reference`: an optional human-curated reference answer.
- `step_metrics`: named timing and token metrics for `IntentValidation`, `ContextRetrieval`, `BaseRAG`, `SpokespersonValidation`, `SemanticPolicyReview` (when a purpose-gated policy applies), and `OutputRedaction`.

Token fields are estimated with a four-characters-per-token heuristic. Answer tokens are split by processing stage in `step_metrics`; `spokesperson_tokens` estimates the deterministic spokesperson input and output text, while `prompt_tokens`, `completion_tokens`, and `total_tokens` estimate the secondary semantic-review LLM call. These are estimates, not provider billing counts.

This makes it possible to review the original prompt beside the generated answer
or error response without reconstructing the request from the metadata.

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

Do not use model-generated answers as references. Reference answers should be reviewed against the source documents before being used in an academic evaluation.

## Analysis notebook

Open `evaluation_analysis.ipynb` after generating a results file. It reports pass rate, request and step latency, evaluation-stage token usage, and RAGAS scores. It exports PNG and SVG figures to:

```text
tests/performance_evaluation/figures/
```
