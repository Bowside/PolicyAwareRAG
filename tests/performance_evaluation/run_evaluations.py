"""Evaluation harness for the current PolicyAwareRAG Function App.

This script targets the live HTTP route exposed by the Azure Function app:
    POST /api/rag

It calls the current request contract, records end-to-end latency, and pulls the
per-step timing and token estimates from the single request-level audit record.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
FUNCTION_APP_URL = os.getenv("FUNCTION_APP_URL", "http://localhost:7071/api/rag")
FUNCTION_APP_KEY = os.getenv("FUNCTION_APP_KEY")
RESULTS_DIR = Path(__file__).resolve().parent
REFERENCE_ANSWERS_PATH = RESULTS_DIR / "reference_answers.json"


def utc_now() -> str:
    """Return the current UTC time formatted for result filenames.

    Returns:
        A filename-safe UTC timestamp in ``YYYY-MM-DDTHH-MM-SSZ`` format.
    """
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


def get_evaluation_context(audit_record: Dict[str, Any]) -> List[str]:
    """Resolve audited document IDs to document text for grounded evaluation.

    Args:
        audit_record: Request audit record containing candidate document IDs.

    Returns:
        Retrieved document bodies in audit order, or an empty list when the
        audit record or Cosmos configuration is unavailable.
    """
    document_ids = audit_record.get("candidateDocumentIds") or []
    if not document_ids:
        for step in audit_record.get("pipelineSteps") or []:
            if isinstance(step, dict) and step.get("candidateDocumentIds"):
                document_ids = step["candidateDocumentIds"]
                break
    if not document_ids:
        return []
    cosmos_endpoint = os.getenv("COSMOSDB_ENDPOINT")
    cosmos_key = os.getenv("COSMOSDB_KEY")
    if not cosmos_endpoint or not cosmos_key:
        return []

    try:
        from azure.cosmos import CosmosClient
    except Exception:
        return []

    try:
        database_name = os.getenv("COSMOSDB_DATABASE", "policy_rag_db")
        container_name = os.getenv("COSMOSDB_COLLECTION", "EnronEmailVectorStore")
        client = CosmosClient(url=cosmos_endpoint, credential=cosmos_key)
        container = client.get_database_client(database_name).get_container_client(container_name)
        context_by_id: Dict[str, str] = {}
        for document_id in document_ids:
            records = list(
                container.query_items(
                    query="SELECT c.id, c.subject, c.body FROM c WHERE c.id = @id",
                    parameters=[{"name": "@id", "value": str(document_id)}],
                    enable_cross_partition_query=True,
                )
            )
            if records:
                record = records[0]
                context_by_id[str(document_id)] = str(record.get("body") or record.get("subject") or "")
        return [context_by_id[str(document_id)] for document_id in document_ids if str(document_id) in context_by_id]
    except Exception:
        return []


def load_reference_answers(path: Path = REFERENCE_ANSWERS_PATH) -> Dict[str, str]:
    """Load optional human-curated reference answers.

    Args:
        path: JSON file mapping exact evaluation questions to reference answers.

    Returns:
        A question-to-reference-answer mapping, or an empty mapping if absent.
    """
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _normalize_reference_lookup(value: str) -> str:
    """Normalize a question for stable comparison across variants."""
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def resolve_reference_answer(
    case: Optional[Dict[str, Any]],
    user_query: str,
    reference_answers: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Resolve the best available reference answer for a generated evaluation case.

    The evaluation harness builds dynamic prompts from a catalog of case templates,
    while the curated reference file stores a prior set of canonical questions. This
    helper falls back from exact key matching to a case-type-aware lookup so the
    evaluator still has reference data even when the concrete subject phrase varies.
    """
    if reference_answers is None:
        reference_answers = load_reference_answers()
    if not reference_answers:
        return None

    if user_query:
        exact = reference_answers.get(user_query)
        if exact:
            return exact

        normalized_query = _normalize_reference_lookup(user_query)
        for key, answer in reference_answers.items():
            if _normalize_reference_lookup(key) == normalized_query:
                return answer

    if not case:
        return None

    case_type = str(case.get("case_type") or "").lower()
    hints_by_case_type = {
        "allow_observer_metadata": ["metadata", "sender domains", "transmission metadata"],
        "allow_observer_routing": ["routing", "distribution lists", "email routing"],
        "allow_observer_triage": ["triage", "compliance triage", "legal and compliance triage"],
        "allow_support_customer": ["customer support", "retail counterparty", "customer service"],
        "allow_support_case": ["case management", "grievance", "hr and grievance"],
        "allow_support_incident": ["incident", "triage evidence", "trading desk incident"],
        "allow_privacy_compliance": ["compliance risks", "ferc", "sec compliance"],
        "allow_privacy_fraud": ["fraud indicators", "misrepresentation", "fraud"],
        "allow_privacy_security": ["security review", "security", "it access"],
        "allow_privacy_privacy": ["redact", "pii", "sensitive compensation"],
        "allow_admin_full_access": ["governance", "retention records", "authorized legal governance"],
    }
    hints = hints_by_case_type.get(case_type, [])
    for key, answer in reference_answers.items():
        key_norm = _normalize_reference_lookup(key)
        if any(hint in key_norm for hint in hints):
            return answer
    return None


def extract_step_metrics(audit_record: Dict[str, Any], user_query: str) -> List[Dict[str, Any]]:
    """Convert pipeline audit steps into compact evaluation metrics.

    Args:
        audit_record: Request-level audit record from Cosmos DB.
        user_query: Original query used as a fallback for token estimation.

    Returns:
        A list of normalized step metric dictionaries.
    """
    steps: List[Dict[str, Any]] = []
    pipeline_steps = audit_record.get("pipelineSteps") or audit_record.get("pipeline_steps") or []
    if not isinstance(pipeline_steps, list):
        return steps

    for step in pipeline_steps:
        if not isinstance(step, dict):
            continue
        telemetry = step.get("telemetry") or {}
        if not isinstance(telemetry, dict):
            telemetry = {}
        step_name = step.get("stepName") or step.get("step_name") or step.get("name")
        if not isinstance(step_name, str) or not step_name.strip():
            continue
        step_record = {
            "stepName": step_name.strip(),
            "executionStatus": step.get("executionStatus") or step.get("execution_status") or "UNKNOWN",
            "latency_ms": float(telemetry.get("latencyMs") or telemetry.get("elapsedMs") or telemetry.get("responseTimeMs") or 0),
            "query_tokens": estimate_tokens(step.get("userQuery") or user_query),
            "answer_tokens": float(
                telemetry.get("answerTokens")
                or telemetry.get("responseTokens")
                or estimate_tokens(telemetry.get("answerLength") or telemetry.get("responseLength") or 0)
            ),
            "input_answer_tokens": float(telemetry.get("inputAnswerTokens") or 0),
            "output_answer_tokens": float(telemetry.get("outputAnswerTokens") or 0),
            "prompt_tokens": float(telemetry.get("promptTokens") or 0),
            "completion_tokens": float(telemetry.get("completionTokens") or 0),
            "total_tokens": float(
                telemetry.get("totalTokens")
                or telemetry.get("spokespersonTokens")
                or 0
            ),
            "spokesperson_tokens": float(
                telemetry.get("spokespersonTokens")
                or (
                    telemetry.get("inputAnswerTokens") or 0
                ) + (
                    telemetry.get("outputAnswerTokens") or 0
                )
                if step_name.strip() == "SpokespersonValidation"
                else 0
            ),
            "review_decision": telemetry.get("reviewDecision"),
            "review_required": bool(telemetry.get("reviewRequired", step_name.strip() == "SemanticPolicyReview")),
            "redacted": bool(telemetry.get("redacted", False)),
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
    "communications regarding Project Raptor and LJM partnerships",
    "the 'Death Star' and 'Fat Boy' California trading strategy emails",
    "communications regarding the Dabhol Power Company and Indian political risk",
    "Vince Kaminski's risk analysis of the off-balance-sheet entities",
    "the broadband operations and Blockbuster partnership correspondence",
    "Jeff Skilling's directives on mark-to-market accounting",
    "FERC regulatory inquiry responses regarding market manipulation",
    "Andy Fastow's internal memos on SPE capitalization",
    "daily Value-at-Risk (VAR) limit escalations on the gas trading desk",
    "employee performance review committee (PRC) ranking feedback",
    "Sherron Watkins' whistleblower warnings to Kenneth Lay",
    "Arthur Andersen audit document retention and destruction policies",
    "Enron Energy Services (EES) retail contract restructuring and losses",
    "the Azurix water venture spin-off and subsequent asset sell-offs",
    "Transwestern Pipeline capacity allocations and pricing discussions",
    "the JEDI and Chewco partnership structures and buyout negotiations",
    "Portland General Electric (PGE) integration and deregulation lobbying",
    "'Get Shorty' and 'Ricochet' gaming tactics in the California ISO market",
    "weather derivatives trading volumes and EnronOnline (EOL) launch metrics",
    "employee 401(k) lockdown period complaints and executive stock sales",
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
        ("allow_observer_metadata", ["business-observer"], "metadata_review", "summarise", "Review the transmission metadata and sender domains for {}."),
        ("allow_observer_routing", ["business-observer"], "routing", "summarise", "Summarize the email routing and distribution lists used in {}."),
        ("allow_observer_triage", ["business-observer"], "triage", "retrieve", "Retrieve the legal and compliance triage details from {}."),
        ("allow_support_customer", ["customer-support-specialist"], "customer_support", "summarise", "Summarize the retail counterparty and customer support activity in {}."),
        ("allow_support_case", ["customer-support-specialist"], "case_management", "audit", "Audit the internal HR and grievance case-management history in {}."),
        ("allow_support_incident", ["customer-support-specialist"], "incident_triage", "retrieve", "Retrieve trading desk incident-triage evidence from {}."),
        ("allow_privacy_compliance", ["privacy-compliance-analyst"], "compliance_review", "summarise", "Review the FERC and SEC compliance risks discussed in {}."),
        ("allow_privacy_fraud", ["privacy-compliance-analyst"], "fraud_detection", "audit", "Audit {} for financial misrepresentation or fraud indicators."),
        ("allow_privacy_security", ["privacy-compliance-analyst"], "security_review", "retrieve", "Retrieve IT access and security-review evidence from {}."),
        ("allow_privacy_privacy", ["privacy-compliance-analyst"], "privacy_review", "redact", "Redact employee PII and sensitive compensation findings from {}."),
        ("allow_admin_full_access", ["pii-data-governance-admin"], "case_management", "export", "Export the authorized legal governance and retention records for {}."),
        ("allow_observer_timeline", ["business-observer"], "timeline_reconstruction", "summarise", "Summarize the chronological timeline of events and key decisions in {}."),
        ("allow_observer_trends", ["business-observer"], "sentiment_analysis", "summarise", "Summarize the overall employee sentiment and communication trends regarding {}."),
        ("allow_support_complaints", ["customer-support-specialist"], "complaint_handling", "retrieve", "Retrieve the external vendor and partner complaints related to {}."),
        ("allow_support_escalation", ["customer-support-specialist"], "escalation_tracking", "summarise", "Summarize the management escalation paths and resolution times for {}."),
        ("allow_privacy_retention", ["privacy-compliance-analyst"], "data_retention", "audit", "Audit the document retention and deletion logs associated with {}."),
        ("allow_privacy_insider", ["privacy-compliance-analyst"], "insider_trading", "audit", "Audit {} for indications of insider trading or undisclosed material knowledge."),
        ("allow_privacy_whistleblower", ["privacy-compliance-analyst"], "whistleblower_protection", "redact", "Redact the identities of whistleblowers and confidential informants in {}."),
        ("allow_admin_access_logs", ["pii-data-governance-admin"], "access_control", "retrieve", "Retrieve the system access logs and permission changes related to {}."),
        ("allow_admin_e_discovery", ["pii-data-governance-admin"], "e_discovery", "export", "Export the complete e-discovery package and litigation hold records for {}."),
    ]
    for case_type, roles, purpose, action, question_template in allowed_case_types:
        for index, subject in enumerate(_CASE_VARIANTS):
            acceptable = (
                ["allow", "allow_redacted"]
                if "privacy" in case_type or "observer" in case_type
                else None
            )
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
        "includeEvaluationDetails": os.getenv("ENABLE_EVALUATION_DETAILS", "false").lower() == "true",
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
    base_answer = str(response_json.get("evaluationDetails", {}).get("baseAnswer") or answer)
    reference_answers = load_reference_answers()
    reference_answer = resolve_reference_answer(case, user_query, reference_answers)
    sources = response_json.get("sources") or []
    evaluation_contexts = get_evaluation_context(audit_record)
    actual_outcome = normalize_outcome(response_json, response.status_code)

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
        "base_answer": base_answer,
        "reference_answer": reference_answer,
        "evaluation_contexts": evaluation_contexts,
        "correlationId": correlation_id,
        "passed": actual_outcome in case.get(
            "acceptable_outcomes",
            [case.get("expected_outcome")],
        ),
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
