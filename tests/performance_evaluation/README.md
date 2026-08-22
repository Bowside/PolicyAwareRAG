# Performance Evaluation Guide

This folder contains the asynchronous evaluation harness for the Policy-Aware RAG workflow.

## What This Runs

The script [run_evaluations.py](run_evaluations.py) sends test prompts to the Durable Function endpoint, waits for orchestration completion, validates expected policy outcomes, and writes a timestamped results file.

Output files are written in this folder using the pattern:

- `evaluation_resultsYYYY-MM-DDTHH-MM-SSZ.json`

## Prerequisites

1. Python environment is set up and dependencies are installed.
2. Azure Function host is running.
3. Required environment variables are set.

Required variables:

- `FUNCTION_APP_URL` (example: `http://localhost:7071/api/orchestrators/start`)
- `FUNCTION_APP_KEY` (required if your endpoint enforces function key auth)

Optional variables:

- `COSMOS_ENRON_COLLECTION` (container override sent in payload)
- `EVAL_SAMPLE_SIZE` (default sample size if `--sample-size` is omitted)
- `EVAL_CASE_TYPE` (default case type filter if `--case-type` is omitted)
- `EVAL_WARMUP_COUNT` (warmup request count, default 0)
- `EVAL_RUN_ID` (explicit run-level correlation ID)
- `EVAL_CONTEXT_WINDOW_SIZE` (`random`, `small`, `medium`, or `large`; default `random`)
- `EVAL_CONTEXT_WINDOW_SEED` (optional deterministic seed when using `random`)

## Start the Function Host

From the repo root, run:

```powershell
func host start
```

Or use the VS Code task `func: host start`.

## Run Evaluation Cycle

From the repo root:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py
```

This runs the default sample size (100 unless overridden by `EVAL_SAMPLE_SIZE`).

Recommended for clear Cosmos correlation:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py --run-id fix-check-001 --warmup-count 0
```

Use a larger retrieval context window:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py --context-window-size medium
```

Use randomized context windows per request (default behavior):

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py --context-window-size random
```

Make random selection reproducible:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py --context-window-size random --context-window-seed 42
```

T-shirt size mapping:

- `small` = top_k 10
- `medium` = top_k 20
- `large` = top_k 40
- `random` = each request samples one of `small` / `medium` / `large`

## Run a Small Sample (Recommended for Fix Validation)

Run 5 mixed prompts:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py -n 5
```

Run 3 prompts for one case type:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py -n 3 --case-type adversarial-injection
```

Run 5 prompts with an explicit correlation ID:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py -n 5 --run-id smoke-2026-08-22 --warmup-count 0
```

Run a quick medium-window smoke test:

```powershell
c:/Users/dillo/Source/Repos/PolicyAwareRAG/.venv/Scripts/python.exe tests/performance_evaluation/run_evaluations.py -n 5 --context-window-size medium --warmup-count 0 --run-id medium-smoke-001
```

## Common Case Types

- `positive-admin`
- `positive-privacy`
- `positive-observer`
- `negative-support`
- `negative-privacy`
- `adversarial-allow`
- `adversarial-deny`
- `adversarial-role-spoof`
- `adversarial-injection`
- `adversarial-pii-leak`
- `adversarial-redaction-bypass`
- `cross-policy-mismatch-1`
- `cross-policy-mismatch-2`
- `constraint-violation`

## What to Check After a Run

1. Console summary:
- Total/passed/failed/skipped
- Pass rate
- Timing breakdown (post, polling, processing)

2. Results JSON:
- `test_summary`
- `timing_summary`
- `case_type_breakdown`
- `results` (per-request details including `transaction_id`, `evaluation_run_id`, `durable_instance_id`, and response echo fields)
- Confirm context-window fields per request: `context_window_size`, `context_window_top_k`, and response match fields

## Correlating With Cosmos AuditStorage

Each request now includes and records:

- `transaction_id` (sent by evaluator)
- `evaluation_run_id` (run-level marker)
- `request_query_text`

The orchestration response echoes:

- `response_transaction_id`
- `response_query_text`
- `response_evaluation_run_id`

When these matches are available, `transaction_id_match`, `query_text_match`, and `evaluation_run_id_match` will be `true`.

In Cosmos, filter by `evaluationRunId` first, then match by `transactionId`.

## Troubleshooting

- `FUNCTION_APP_URL=None`: set `FUNCTION_APP_URL` before running.
- `FUNCTION_APP_KEY=<not set>`: set key if endpoint requires auth.
- Timeouts or high polling time: verify Function host health and Durable runtime status endpoint reachability.
- Unexpected denials/allows: inspect each record's `expected_outcome`, `actual_outcome`, `policy_evaluation`, and `dpi_audit` fields.
