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
import random
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
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
    """Return the current UTC time formatted for result filenames."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


def estimate_tokens(value: Any) -> int:
    """Estimate token usage from a value using a four-characters-per-token heuristic.

    Args:
        value: Value whose textual representation should be estimated.

    Returns:
        An integer token estimate, or zero for empty values.
    """
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if not text:
        return 0
    return max(1, round(len(text) / 4.0))


def get_audit_record(correlation_id: Optional[str]) -> Dict[str, Any]:
    """Fetch the request-level audit record for a correlation ID.

    Args:
        correlation_id: Correlation identifier returned by the Function App.

    Returns:
        The matching Cosmos DB record, or an empty dictionary when unavailable.
    """
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
    """Convert pipeline audit steps into compact evaluation metrics.

    Args:
        audit_record: Request-level audit record from Cosmos DB.
        user_query: Original query used as a fallback for token estimation.

    Returns:
        A list of normalized step metric dictionaries.
    """
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
            "latency_ms": float(telemetry.get("latencyMs") or telemetry.get("elapsedMs") or telemetry.get("responseTimeMs") or 0),
            "query_tokens": estimate_tokens(step.get("userQuery") or user_query),
            "answer_tokens": int(telemetry.get("answerLength") or telemetry.get("responseLength") or 0),
            "document_count": telemetry.get("documentMatchCount"),
            "reason": step.get("reason"),
        }
        steps.append(step_record)
    return steps


def normalize_outcome(response_payload: Dict[str, Any], status_code: int) -> str:
    """Map an HTTP response into an evaluation outcome category.

    Args:
        response_payload: Decoded JSON response from the Function App.
        status_code: HTTP status code returned by the Function App.

    Returns:
        One of ``deny``, ``allow``, ``allow_redacted``, or ``unknown``.
    """
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


_CASE_VARIANTS = [
    "the California energy trading thread",
    "the customer account correspondence",
    "the quarterly capacity discussion",
    "the market operations emails",
    "the contract approval conversation",
    "the regional scheduling updates",
    "the regulatory inquiry messages",
    "the customer service escalation",
    "the risk management review",
    "the internal planning thread",
]


def _make_case(
    case_type: str,
    question: str,
    roles: List[str],
    purpose: str,
    action: str,
    index: int,
    expected_outcome: str = "allow",
    acceptable_outcomes: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Create one evaluation request record.

    Args:
        case_type: Policy-oriented category for the case.
        question: Natural-language request sent to the Function App.
        roles: ODRL roles assigned to the simulated user.
        purpose: ODRL purpose for the request.
        action: ODRL action requested by the simulated user.
        index: Zero-based variant index used to create a unique user ID.
        expected_outcome: Primary expected response category.
        acceptable_outcomes: Optional alternative categories that also pass.

    Returns:
        A case dictionary suitable for ``run_case``.
    """
    case = {
        "case_type": case_type,
        "question": question,
        "userRoles": roles,
        "purpose": purpose,
        "action": action,
        "userId": f"eval-{case_type}-{index + 1}",
        "expected_outcome": expected_outcome,
    }
    if acceptable_outcomes:
        case["acceptable_outcomes"] = acceptable_outcomes
    return case


def build_cases() -> List[Dict[str, Any]]:
    """Build a balanced catalog of 120 policy-oriented evaluation cases.

    Returns:
        Ten cases for each of twelve policy case types, covering allowed and
        prohibited role, purpose, and action combinations.
    """
    cases: List[Dict[str, Any]] = []

    allowed_case_types = [
        ("allow_observer_metadata", ["business-observer"], "metadata_review", "summarise", "Review the metadata for {}."),
        ("allow_observer_routing", ["business-observer"], "routing", "summarise", "Summarize the routing information in {}."),
        ("allow_observer_triage", ["business-observer"], "triage", "retrieve", "Retrieve the relevant triage details from {}."),
        ("allow_support_customer", ["customer-support-specialist"], "customer_support", "summarise", "Summarize the customer support activity in {}."),
        ("allow_support_case", ["customer-support-specialist"], "case_management", "audit", "Audit the case-management history in {}."),
        ("allow_support_incident", ["customer-support-specialist"], "incident_triage", "retrieve", "Retrieve incident-triage evidence from {}."),
        ("allow_privacy_compliance", ["privacy-compliance-analyst"], "compliance_review", "summarise", "Review the compliance risks in {}."),
        ("allow_privacy_fraud", ["privacy-compliance-analyst"], "fraud_detection", "audit", "Audit {} for fraud indicators."),
        ("allow_privacy_security", ["privacy-compliance-analyst"], "security_review", "retrieve", "Retrieve security-review evidence from {}."),
        ("allow_privacy_privacy", ["privacy-compliance-analyst"], "privacy_review", "redact", "Redact sensitive findings from {}."),
        ("allow_admin_full_access", ["pii-data-governance-admin"], "case_management", "export", "Export the authorized governance records for {}."),
    ]
    for case_type, roles, purpose, action, question_template in allowed_case_types:
        for index, subject in enumerate(_CASE_VARIANTS):
            acceptable = ["allow", "allow_redacted"] if "privacy" in case_type else None
            cases.append(
                _make_case(
                    case_type,
                    question_template.format(subject),
                    roles,
                    purpose,
                    action,
                    index,
                    acceptable_outcomes=acceptable,
                )
            )

    restricted_roles = [
        ("business-observer", "routing"),
        ("customer-support-specialist", "customer_support"),
        ("privacy-compliance-analyst", "privacy_review"),
    ]
    for index, subject in enumerate(_CASE_VARIANTS):
        role, purpose = restricted_roles[index % len(restricted_roles)]
        cases.append(
            _make_case(
                "deny_restricted_export",
                f"Export all personal information from {subject}.",
                [role],
                purpose,
                "export",
                index,
                expected_outcome="deny",
            )
        )

    return cases


def select_cases(
    cases: Iterable[Dict[str, Any]],
    max_tests: Optional[int],
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """Select a reproducible, round-robin sample across case types.

    Args:
        cases: Available evaluation cases grouped by their ``case_type`` field.
        max_tests: Maximum number of cases to return, or ``None`` for all cases.
        seed: Random seed used to shuffle each case-type group.

    Returns:
        A balanced sample that cycles through case types before taking a second
        case from any type.

    Raises:
        ValueError: If ``max_tests`` is less than one.
    """
    all_cases = list(cases)
    if max_tests is None:
        return all_cases
    if max_tests < 1:
        raise ValueError("max_tests must be at least 1")
    if max_tests >= len(all_cases):
        return all_cases

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for case in all_cases:
        grouped.setdefault(case["case_type"], []).append(case)

    generator = random.Random(seed)
    for group in grouped.values():
        generator.shuffle(group)

    selected: List[Dict[str, Any]] = []
    while len(selected) < max_tests:
        made_progress = False
        for group in grouped.values():
            if group and len(selected) < max_tests:
                selected.append(group.pop())
                made_progress = True
        if not made_progress:
            break
    return selected


def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one evaluation case against the configured Function App.

    Args:
        case: Evaluation request definition produced by ``build_cases``.

    Returns:
        A result record containing the original prompt, raw response text,
        parsed response, latency, audit metrics, and pass/fail status.
    """
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
    response_text = getattr(response, "text", "")
    if not response_text:
        response_text = json.dumps(response_json, ensure_ascii=False)

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
        "original_prompt": user_query,
        "request_payload": payload,
        "response_text": response_text,
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
        "passed": actual_outcome in case.get(
            "acceptable_outcomes",
            [case.get("expected_outcome")],
        ),
        "ragas": ragas_result,
        "timestamp": utc_now(),
    }


def run_suite(
    cases: Optional[Iterable[Dict[str, Any]]] = None,
    max_threads: int = 4,
    max_tests: Optional[int] = None,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """Run a sampled evaluation suite concurrently and save its results.

    Args:
        cases: Optional custom case iterable; defaults to ``build_cases()``.
        max_threads: Maximum number of concurrent HTTP evaluations.
        max_tests: Maximum number of cases to sample across case types.
        seed: Random seed used for reproducible case sampling.

    Returns:
        Evaluation results in the selected case order.

    Raises:
        ValueError: If ``max_threads`` or ``max_tests`` is less than one.
    """
    if cases is None:
        cases = build_cases()
    if max_threads < 1:
        raise ValueError("max_threads must be at least 1")
    cases = select_cases(cases, max_tests=max_tests, seed=seed)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = list(executor.map(run_case, cases))
    output_path = RESULTS_DIR / f"evaluation_results_{utc_now()}.json"
    output_path.write_text(json.dumps({"results": results}, indent=2), encoding='utf-8')
    print(f"Saved {len(results)} evaluations to {output_path}")
    return results


def main() -> None:
    """Parse command-line options and run the configured evaluation suite."""
    import argparse

    parser = argparse.ArgumentParser(description="Run the PolicyAwareRAG evaluation suite.")
    parser.add_argument(
        "--max-threads",
        type=int,
        default=4,
        help="Maximum number of evaluations to run concurrently (default: 4).",
    )
    parser.add_argument(
        "--max-tests",
        type=int,
        default=None,
        help="Number of cases to sample across case types (default: all cases).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed used to make case sampling reproducible (default: 42).",
    )
    args = parser.parse_args()

    print(f"Using Function App endpoint: {FUNCTION_APP_URL}")
    print(f"Using Cosmos audit log: {'yes' if os.getenv('COSMOSDB_ENDPOINT') and os.getenv('COSMOSDB_KEY') else 'no'}")
    results = run_suite(
        max_threads=args.max_threads,
        max_tests=args.max_tests,
        seed=args.seed,
    )
    pass_count = sum(1 for item in results if item["passed"])
    print(f"Pass rate: {pass_count}/{len(results)} ({(pass_count / len(results)):.2%})")


if __name__ == "__main__":
    main()
