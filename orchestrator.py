"""Durable Functions orchestration for policy-aware retrieval and compliance.

This module coordinates the end-to-end request flow:
- validate the ODRL policy against the principal's role and declared intent
- detect count-style sender queries and handle them directly
- retrieve candidate email chunks using vector similarity and security filters
- evaluate the retrieval through the multi-agent compliance graph
- generate a response, run the compliance guard, and optionally trigger redaction
- emit a structured audit event for downstream monitoring and review
"""

import logging
import os
import re
import uuid
from datetime import datetime, timezone

import azure.durable_functions as df

from compliance_guard import compliance_guard
from graph_state import MultiAgentGraph, permissive_agent, restrictive_agent
from policy_validator import PolicyPurposeValidator
from retriever import ConflictAwareRetriever


def _build_query_embedding(query_text: str, query_embedding: list) -> list:
    """Return a usable query embedding, generating one when the caller provides none.

    Several orchestration paths accept an embedding from the caller. When the value
    is missing or malformed, this function falls back to the configured sentence
    transformer model and uses it to encode the query text.

    Args:
        query_text: Raw user query text to encode.
        query_embedding: Caller-provided embedding candidate, if any.

    Returns:
        list: Embedding floats suitable for vector retrieval, or an empty list when
            generation fails.
    """
    if query_embedding and len(query_embedding) >= 16:
        return query_embedding

    if query_embedding:
        logging.warning(
            "Ignoring malformed query embedding of length %s; generating a fresh embedding for vector search.",
            len(query_embedding),
        )

    try:
        from sentence_transformers import SentenceTransformer
        model_name = os.environ.get("EMBEDDING_MODEL")
        if not model_name:
            raise ValueError("EMBEDDING_MODEL is not configured.")
        model = SentenceTransformer(model_name)
        embedding = model.encode([query_text or ""], normalize_embeddings=False)[0]
        return embedding.tolist() if hasattr(embedding, "tolist") else list(embedding)
    except Exception as exc:
        logging.warning("Unable to build a valid query embedding for Cosmos retrieval: %s", exc)
        return []


def _format_reasoning_trail(reasoning: list[str]) -> str:
    """Join a reasoning trail into a compact audit string.

    Args:
        reasoning: Ordered list of reasoning statements collected from policy
            evaluation and decisioning.

    Returns:
        str: Semicolon-separated reasoning string for storage in the audit payload.
    """
    if not reasoning:
        return ""
    return "; ".join(reasoning)


def _map_guard_status(guard_status: str, outcome_status: str, enforcement_action_type: str) -> str:
    """Map guard and outcome state to the audit-facing compliance status.

    Args:
        guard_status: Status returned by the compliance guard.
        outcome_status: Final payload status from the orchestrated outcome.
        enforcement_action_type: Enforcement action selected by the orchestrator.

    Returns:
        str: Normalized compliance status label for the audit record.
    """
    if enforcement_action_type == "Partial_Redaction":
        return "Sanitized"
    if outcome_status == "denied":
        return "Blocked"
    if guard_status == "Fail":
        return "Sanitized"
    return "Passed"


def build_audit_event(
    transaction_id: str,
    start_time: datetime,
    end_time: datetime,
    duration_seconds: float,
    principal: dict,
    odrl_policy: dict,
    query_text: str,
    query_embedding: list,
    action: str,
    cosmos_collection: str,
    retrieved: list,
    eval_detail: dict,
    allowed: bool,
    guard: dict,
    enforcement_action_type: str,
    final_payload: dict,
    security_filters: dict | None = None,
    decision_graph: dict | None = None,
) -> dict:
    """Build the structured audit event payload for a completed orchestration.

    The audit event captures the request context, evaluated policy state,
    enforcement decision, and final user-facing outcome. It is designed to be
    written to the Cosmos audit container via the StoreAuditEventActivity activity.

    Args:
        transaction_id: Unique request identifier.
        start_time: Orchestration start time in UTC.
        end_time: Orchestration completion time in UTC.
        duration_seconds: End-to-end orchestration duration in seconds.
        principal: Principal details such as userId, role, and declaredIntent.
        odrl_policy: ODRL policy that was evaluated for the request.
        query_text: Original query text submitted by the caller.
        query_embedding: Embedding values used in vector retrieval.
        action: Requested action type (for example, summarise or count).
        cosmos_collection: Cosmos DB collection name used during retrieval.
        retrieved: Retrieved documents or chunks consumed during the request.
        eval_detail: Policy evaluation result and reasoning details.
        allowed: Whether the policy allowed the request at validation time.
        guard: Compliance guard status returned after response generation.
        enforcement_action_type: Final enforcement decision (Allow, Deny, Partial_Redaction).
        final_payload: Final response payload returned to the user.
        security_filters: Security filters derived from the policy.
        decision_graph: Multi-agent decision graph result.

    Returns:
        dict: Structured audit event payload suitable for storage.
    """
    matched_rules = eval_detail.get("matchedRules") or []
    matched_policy_uid = matched_rules[0] if matched_rules else odrl_policy.get("uid", "")
    outcome_status = final_payload.get("status", "")

    return {
        "id": transaction_id,
        "transactionId": transaction_id,
        "timestamp": start_time.isoformat(),
        "startTime": start_time.isoformat(),
        "endTime": end_time.isoformat(),
        "durationSeconds": duration_seconds,
        "principal": {
            "userId": principal.get("userId", ""),
            "role": principal.get("role", ""),
            "declaredIntent": principal.get("declaredIntent", ""),
        },
        "request": {
            "queryText": query_text,
            "queryEmbedding": query_embedding,
            "action": action,
            "securityFilters": security_filters or {},
            "cosmosCollectionId": cosmos_collection,
        },
        "odrlPolicy": odrl_policy,
        "policyEvaluation": {
            "matchedPolicyUid": matched_policy_uid,
            "ruleType": "Permission" if allowed else "Prohibition",
            "constraintSatisfaction": bool(eval_detail.get("satisfied")),
            "reasoningTrail": _format_reasoning_trail(eval_detail.get("reasoning") or []),
        },
        "enforcementAction": {
            "actionType": enforcement_action_type,
            "filteredNodesCount": len(retrieved),
            "complianceGuardStatus": _map_guard_status(guard.get("status", ""), outcome_status, enforcement_action_type),
        },
        "decisionGraph": decision_graph or {},
        "outcome": final_payload,
    }


def _build_no_results_payload() -> dict:
    """Build the standard payload returned when retrieval finds nothing.

    Returns:
        dict: User-facing payload indicating no relevant context was found.
    """
    return {
        "status": "ok",
        "outcomeType": "no_results",
        "result": "No relevant context was retrieved for this request.",
    }


_COUNT_QUERY_PATTERNS = (
    re.compile(r"^\s*(?:how many|count|number of)\s+emails?\s+(?:did|does|do|has|have)?\s*(?P<sender>.+?)\s+send\s*\??\s*$", re.IGNORECASE),
    re.compile(r"^\s*(?:how many|count|number of)\s+emails?\s+from\s+(?P<sender>.+?)\s*\??\s*$", re.IGNORECASE),
)


def _extract_sender_from_count_query(query_text: str) -> str | None:
    """Extract a sender name from a natural-language count query.

    This helper recognizes count-style prompts such as "How many emails from Jane
    Doe?" and extracts the sender portion so it can be passed to the Cosmos
    sender-count query path.

    Args:
        query_text: Natural-language query text.

    Returns:
        str | None: Extracted sender relevant to counting, or None when the query
            is not a supported sender-count pattern.
    """
    normalized_query = " ".join((query_text or "").strip().split())
    for pattern in _COUNT_QUERY_PATTERNS:
        match = pattern.match(normalized_query)
        if not match:
            continue

        sender = match.group("sender").strip().strip("?.!,")
        sender = re.sub(r"^(?:the|a|an)\s+", "", sender, flags=re.IGNORECASE)
        return sender or None

    return None


def _format_sender_label(sender_query: str) -> str:
    """Format a sender query into a display-friendly label.

    Args:
        sender_query: Sender text extracted from the query.

    Returns:
        str: Title-cased label for output, or the original email address when an
            address-like string is provided.
    """
    sender_query = (sender_query or "").strip()
    if "@" in sender_query:
        return sender_query
    return sender_query.title()


def _evaluate_multi_agent_graph(retrieved: list[dict], eval_detail: dict) -> dict:
    """Run the multi-agent policy decision graph over retrieved chunks.

    The graph aggregates restrictive and permissive signals to decide whether the
    retrieved context is allowed, partially redacted, or denied.

    Args:
        retrieved: Retrieved chunks to evaluate.
        eval_detail: Policy evaluation detail record.

    Returns:
        dict: Multi-agent decision graph output with decision and reasoning.
    """
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    return graph.evaluate(retrieved, eval_detail)

def orchestrator_function(context: df.DurableOrchestrationContext):
    """Run the durable orchestration for policy-aware response generation.

    This orchestration validates policy intent, resolves sender-count shortcuts,
    retrieves relevant content, invokes the multi-agent decision graph, and then
    produces either an allowed response, a redacted response, or a denial.

    Args:
        context: Durable Functions orchestration context for the current instance.

    Returns:
        dict: Final orchestrated payload describing allow, deny, or redaction.
    """
    input_payload = context.get_input() or {}
    transaction_id = str(uuid.uuid4())
    start_time = datetime.now(timezone.utc)

    principal = input_payload.get("principal", {})
    odrl_policy = input_payload.get("odrl_policy", {})
    query_text = input_payload.get("query_text") or input_payload.get("query") or ""
    action = input_payload.get("action", "summarise")
    cosmos_collection = input_payload.get("cosmos_collection", "EnronEmailVectorStore")

    pv = PolicyPurposeValidator(odrl_policy)
    allowed, eval_detail = pv.evaluate(principal.get("role",""), principal.get("declaredIntent",""), action)
    retrieved = []
    handled_count_query = False
    query_embedding = []
    decision_graph = {"decision": "Allow", "reasoning": {"signals": [], "tallies": {"deny": 0, "redact": 0, "allow": 0}}}
    guard = {"status": "NotRun", "action": "Block", "findings": []}
    enforcement_action_type = "Deny"
    final_payload = {"status": "denied", "result": "Request denied due to policy restrictions."}

    if not allowed:
        generated = "Request denied due to policy restrictions."
        guard = {"status": "NotRun", "action": "Block", "findings": ["policy_validator_declined"]}
        enforcement_action_type = "Deny"
        final_payload = {
            "status": "denied",
            "reason": eval_detail.get("reasoning", []),
            "result": generated,
            "policyEvaluation": eval_detail,
        }
    else:
        count_sender = _extract_sender_from_count_query(query_text)
        if count_sender:
            retriever = ConflictAwareRetriever(container_name=cosmos_collection)
            retrieved_count = retriever.count_by_sender(count_sender)
            sender_label = _format_sender_label(count_sender)

            generated = f"{sender_label} sent {retrieved_count} email{'s' if retrieved_count != 1 else ''}."
            guard = {"status": "Pass", "action": "Release", "findings": []}
            enforcement_action_type = "Allow"
            final_payload = {
                "status": "ok",
                "outcomeType": "count_result",
                "result": generated,
                "count": retrieved_count,
                "subject": sender_label,
                "retrieved": [],
            }
            handled_count_query = True
        else:
            # Retrieval is intentionally broad; policy enforcement happens before the RAG context is assembled.
            query_embedding = _build_query_embedding(query_text, input_payload.get("query_embedding", []))
            retriever = ConflictAwareRetriever(container_name=cosmos_collection)
            retrieved = retriever.retrieve(query_embedding, {}, top_k=10)
            decision_graph = _evaluate_multi_agent_graph(retrieved, eval_detail)

        if handled_count_query:
            pass
        elif not retrieved:
            generated = "No relevant context was retrieved for this request."
            guard = {"status": "Pass", "action": "Release", "findings": []}
            enforcement_action_type = "Allow"
            final_payload = _build_no_results_payload()
            final_payload["retrieved"] = []
        elif decision_graph.get("decision") == "Deny":
            generated = "Request denied due to policy restrictions."
            guard = {"status": "Pass", "action": "Release", "findings": []}
            enforcement_action_type = "Deny"
            final_payload = {
                "status": "denied",
                "reason": decision_graph.get("reasoning", {}),
                "result": generated,
                "decisionGraph": decision_graph,
            }
        else:
            if decision_graph.get("decision") == "Partial_Redaction":
                enforcement_action_type = "Partial_Redaction"
                generated = yield context.call_activity(
                    "GenerateRedactedResponseActivity",
                    {
                        "query_text": query_text,
                        "retrieved": retrieved,
                        "principal": principal,
                        "policy_evaluation": eval_detail,
                        "action": action,
                    },
                )
            else:
                enforcement_action_type = "Allow"
                generated = yield context.call_activity(
                    "GenerateResponseActivity",
                    {
                        "query_text": query_text,
                        "query_embedding": query_embedding,
                        "retrieved": retrieved,
                        "principal": principal,
                        "policy_evaluation": eval_detail,
                        "action": action,
                    },
                )

            guard = compliance_guard(generated, retrieved)
            if guard["status"] == "Fail":
                logging.warning("Compliance guard blocked generated response: %s", guard["findings"])
                generated = yield context.call_activity(
                    "GenerateRedactedResponseActivity",
                    {
                        "query_text": query_text,
                        "retrieved": retrieved,
                        "principal": principal,
                        "policy_evaluation": eval_detail,
                        "action": action,
                    },
                )
                redacted_guard = compliance_guard(generated, retrieved)
                if redacted_guard["status"] == "Pass":
                    enforcement_action_type = "Partial_Redaction"
                else:
                    enforcement_action_type = "Deny"
                guard = redacted_guard

            if enforcement_action_type == "Allow" and guard["status"] == "Fail":
                enforcement_action_type = "Deny"

            if guard["status"] == "Fail":
                final_payload = {"status": "denied", "reason": guard["findings"], "result": generated}
            else:
                final_payload = {"status": "ok", "result": generated, "decisionGraph": decision_graph, "retrieved": retrieved}

    end_time = datetime.now(timezone.utc)
    duration_seconds = (end_time - start_time).total_seconds()

    audit_event = build_audit_event(
        transaction_id=transaction_id,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        principal=principal,
        odrl_policy=odrl_policy,
        query_text=query_text,
        query_embedding=query_embedding,
        action=action,
        cosmos_collection=cosmos_collection,
        retrieved=retrieved,
        eval_detail=eval_detail,
        allowed=allowed,
        guard=guard,
        enforcement_action_type=enforcement_action_type,
        final_payload=final_payload,
        decision_graph=decision_graph,
    )
    store_result = yield context.call_activity("StoreAuditEventActivity", audit_event)
    if isinstance(store_result, dict) and store_result.get("status") != "ok":
        logging.warning("StoreAuditEventActivity returned non-ok status: %s", store_result)

    return final_payload

main = df.Orchestrator.create(orchestrator_function)
