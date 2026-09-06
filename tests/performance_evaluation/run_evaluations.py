"""Evaluation harness for the current PolicyAwareRAG Function App.

This script targets the live HTTP route exposed by the Azure Function app:
    POST /api/rag

It calls the current request contract, records end-to-end latency, pulls the
per-step timing and token estimates from the single request-level audit record,
and optionally computes RAGAS metrics when the framework is installed.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from dotenv import load_dotenv

try:
    from datasets import Dataset
    from ragas import evaluate
    from ragas.metrics import answer_relevancy, context_precision, context_recall, faithfulness
except Exception:  # pragma: no cover - optional dependency fallback
    Dataset = None
    evaluate = None
    answer_relevancy = None
    context_precision = None
    context_recall = None
    faithfulness = None

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

FUNCTION_APP_URL = os.getenv("FUNCTION_APP_URL", "http://localhost:7071/api/rag")
FUNCTION_APP_KEY = os.getenv("FUNCTION_APP_KEY")
RESULTS_DIR = Path(__file__).resolve().parent


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def estimate_tokens(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    return max(1, round(len(text) / 4.0))


def get_audit_record(correlation_id: Optional[str]) -> Dict[str, Any]:
    if not correlation_id:
        return {}
    cosmos_endpoint = os.getenv("COSMOSDB_ENDPOINT")
    cosmos_key = os.getenv("COSMOSDB_KEY")
    cosmos_database = os.getenv("COSMOSDB_DATABASE", "policy_rag_db")
    container_name = os.getenv("COSMOSDB_AUDIT_CONTAINER", "AuditStorage")
    if not cosmos_endpoint or not cosmos_key:
        return {}

    try:
        from azure.cosmos import CosmosClient
    except Exception:
        return {}

    try:
        client = CosmosClient(url=cosmos_endpoint, credential=cosmos_key)
        database = client.get_database_client(cosmos_database)
        container = database.get_container_client(container_name)
        results = list(
            container.query_items(
                query="SELECT * FROM c WHERE c.correlationId = @correlationId",
                parameters=[{"name": "@correlationId", "value": correlation_id}],
                enable_cross_partition_query=True,
            )
        )
        return results[0] if results else {}
    except Exception:
        return {}


def extract_step_metrics(audit_record: Dict[str, Any], user_query: str) -> List[Dict[str, Any]]:
    steps: List[Dict[str, Any]] = []
    pipeline_steps = audit_record.get("pipelineSteps") or []
    if not isinstance(pipeline_steps, list):
        return steps

    for step in pipeline_steps:
        if not isinstance(step, dict):
            continue
        telemetry = step.get("telemetry") or {}
        if not isinstance(telemetry, dict):
            telemetry = {}
        step_name = step.get("stepName", "unknown")
        step_record = {
            "stepName": step_name,
            "executionStatus": step.get("executionStatus", "UNKNOWN"),
            "latency_ms": int(telemetry.get("latencyMs") or telemetry.get("elapsedMs") or telemetry.get("responseTimeMs") or 0),
            "query_tokens": estimate_tokens(step.get("userQuery") or user_query),
            "answer_tokens": int(telemetry.get("answerLength") or telemetry.get("responseLength") or 0),
            "document_count": telemetry.get("documentMatchCount"),
            "reason": step.get("reason"),
        }
        steps.append(step_record)
    return steps


def normalize_outcome(response_payload: Dict[str, Any], status_code: int) -> str:
    if status_code == 403:
        return "deny"
    if not isinstance(response_payload, dict):
        return "unknown"
    answer = str(response_payload.get("answer") or "")
    if "[REDACTED" in answer:
        return "allow_redacted"
    if response_payload.get("policyDenied") is True:
        return "deny"
    if answer.strip():
        return "allow"
    return "unknown"


def build_cases() -> List[Dict[str, Any]]:
    return [
        {
            "case_type": "allow_metadata_review",
            "question": "Summarize the routing information for the California energy trading thread.",
            "userRoles": ["business-observer"],
            "purpose": "routing",
            "action": "summarise",
            "userId": "eval-observer",
            "expected_outcome": "allow",
        },
        {
            "case_type": "allow_compliance_review",
            "question": "Review the compliance risks and key issues in the privacy review emails.",
            "userRoles": ["privacy-compliance-analyst"],
            "purpose": "compliance_review",
            "action": "summarise",
            "userId": "eval-privacy",
            "expected_outcome": "allow",
        },
        {
            "case_type": "deny_export_for_observer",
            "question": "Export all personal information from the Enron corpus.",
            "userRoles": ["business-observer"],
            "purpose": "routing",
            "action": "export",
            "userId": "eval-observer",
            "expected_outcome": "deny",
        },
        {
            "case_type": "deny_export_for_support",
            "question": "Export the full customer contact list for all accounts.",
            "userRoles": ["customer-support-specialist"],
            "purpose": "customer_support",
            "action": "export",
            "userId": "eval-support",
            "expected_outcome": "deny",
        },
        {
            "case_type": "allow_redacted_pii",
            "question": "Provide the routing summary and the contact email for the primary deal lead.",
            "userRoles": ["business-observer"],
            "purpose": "routing",
            "action": "summarise",
            "userId": "eval-observer",
            "expected_outcome": "allow_redacted",
        },
        {
            "case_type": "allow_admin_review",
            "question": "Review the customer support activity and summarize the relevant facts.",
            "userRoles": ["pii-data-governance-admin"],
            "purpose": "case_management",
            "action": "summarise",
            "userId": "eval-admin",
            "expected_outcome": "allow",
        },
    ]


def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "question": case["question"],
        "userRoles": case["userRoles"],
        "purpose": case["purpose"],
        "action": case["action"],
        "userId": case.get("userId", "eval-user"),
    }
    headers = {"Content-Type": "application/json"}
    if FUNCTION_APP_KEY:
        headers["x-functions-key"] = FUNCTION_APP_KEY

    start = time.perf_counter()
    response = requests.post(FUNCTION_APP_URL, json=payload, headers=headers, timeout=180)
    elapsed_ms = round((time.perf_counter() - start) * 1000)

    response_json = {}
    try:
        response_json = response.json()
    except Exception:
        response_json = {}

    correlation_id = response_json.get("correlationId")
    user_query = case["question"]
    audit_record = get_audit_record(correlation_id)
    step_metrics = extract_step_metrics(audit_record, user_query)
    total_step_latency_ms = sum(step.get("latency_ms", 0) for step in step_metrics)

    answer = str(response_json.get("answer") or "")
    sources = response_json.get("sources") or []
    actual_outcome = normalize_outcome(response_json, response.status_code)

    ragas_result = None
    if evaluate is not None and Dataset is not None and answer.strip():
        try:
            dataset = Dataset.from_dict({
                "question": [user_query],
                "answer": [answer],
                "contexts": [[str(item) for item in sources]],
            })
            score_data = evaluate(
                dataset,
                metrics=[
                    answer_relevancy,
                    context_precision,
                    context_recall,
                    faithfulness,
                ],
            )
            ragas_result = {key: float(value) for key, value in score_data.to_dict().items() if isinstance(value, (int, float))}
        except Exception:
            ragas_result = None

    return {
        "case_type": case["case_type"],
        "question": user_query,
        "userRoles": case["userRoles"],
        "purpose": case["purpose"],
        "action": case["action"],
        "expected_outcome": case.get("expected_outcome"),
        "actual_outcome": actual_outcome,
        "status_code": response.status_code,
        "http_latency_ms": elapsed_ms,
        "total_step_latency_ms": total_step_latency_ms,
        "token_counts": {
            "question_tokens": estimate_tokens(user_query),
            "answer_tokens": estimate_tokens(answer),
            "source_tokens": estimate_tokens(json.dumps(sources, ensure_ascii=False)),
        },
        "step_metrics": step_metrics,
        "response": response_json,
        "correlationId": correlation_id,
        "passed": actual_outcome == case.get("expected_outcome"),
        "ragas": ragas_result,
        "timestamp": utc_now(),
    }


def run_suite(cases: Optional[Iterable[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    if cases is None:
        cases = build_cases()

    results = [run_case(case) for case in cases]
    output_path = RESULTS_DIR / f"evaluation_results_{utc_now()}.json"
    output_path.write_text(json.dumps({"results": results}, indent=2), encoding='utf-8')
    print(f"Saved {len(results)} evaluations to {output_path}")
    return results


def main() -> None:
    print(f"Using Function App endpoint: {FUNCTION_APP_URL}")
    print(f"Using Cosmos audit log: {'yes' if os.getenv('COSMOSDB_ENDPOINT') and os.getenv('COSMOSDB_KEY') else 'no'}")
    results = run_suite()
    pass_count = sum(1 for item in results if item["passed"])
    print(f"Pass rate: {pass_count}/{len(results)} ({(pass_count / len(results)):.2%})")


if __name__ == "__main__":
    main()
