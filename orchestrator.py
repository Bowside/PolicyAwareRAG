import logging
import azure.durable_functions as df
from graph_state import MultiAgentGraph, permissive_agent, restrictive_agent
from policy_validator import PolicyPurposeValidator
from retriever import ConflictAwareRetriever
from compliance_guard import compliance_guard
import uuid
from datetime import datetime
import os
import re


def _build_query_embedding(query_text: str, query_embedding: list) -> list:
    """Return a usable query embedding, computing one if needed.

    Args:
        query_text: Raw user query text.
        query_embedding: Caller-provided embedding candidate.

    Returns:
        A list of embedding floats suitable for retrieval.
    """
    if query_embedding and len(query_embedding) >= 16:
        return query_embedding

    try:
        from sentence_transformers import SentenceTransformer

        model_name = os.environ.get("EMBED_MODEL", "all-MiniLM-L6-v2")
        model = SentenceTransformer(model_name)
        embedding = model.encode([query_text or ""], normalize_embeddings=False)[0]
        return embedding.tolist() if hasattr(embedding, "tolist") else list(embedding)
    except Exception as exc:
        logging.warning("Falling back to caller-provided query embedding: %s", exc)
        return query_embedding or []


def _format_reasoning_trail(reasoning: list[str]) -> str:
    """Join a reasoning trail into a compact audit string.

    Args:
        reasoning: Ordered list of reasoning statements.

    Returns:
        A semicolon-separated reasoning string.
    """
    if not reasoning:
        return ""
    return "; ".join(reasoning)


def _map_guard_status(guard_status: str, outcome_status: str, enforcement_action_type: str) -> str:
    """Map guard and outcome state to the audit status label.

    Args:
        guard_status: Status returned by the compliance guard.
        outcome_status: Final payload status.
        enforcement_action_type: Enforcement action chosen by the orchestrator.

    Returns:
        The audit-facing compliance guard status.
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
    database_name: str,
    retrieved: list,
    eval_detail: dict,
    allowed: bool,
    guard: dict,
    enforcement_action_type: str,
    final_payload: dict,
    security_filters: dict | None = None,
    decision_graph: dict | None = None,
) -> dict:
    """Build the audit event payload for a completed orchestration.

    Args:
        transaction_id: Unique identifier for the request.
        start_time: Orchestration start time.
        end_time: Orchestration end time.
        duration_seconds: Total orchestration duration.
        principal: Request principal details.
        odrl_policy: Policy used to evaluate the request.
        query_text: Original user query text.
        query_embedding: Embedding used for retrieval.
        action: Requested action.
        cosmos_collection: Cosmos DB container name.
        database_name: Cosmos DB database name.
        retrieved: Retrieved chunks used by the orchestration.
        eval_detail: Policy evaluation detail record.
        allowed: Whether the policy allowed the request.
        guard: Compliance guard result.
        enforcement_action_type: Final enforcement decision.
        final_payload: Final user-facing response payload.
        security_filters: Policy-derived retrieval filters.
        decision_graph: Multi-agent decision graph result.

    Returns:
        A dictionary shaped for audit storage.
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
            "database": database_name,
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
        "retrieved": retrieved,
        "outcome": final_payload,
    }


def _build_no_results_payload() -> dict:
    """Build the standard payload returned when retrieval finds nothing.

    Returns:
        A user-facing payload indicating no relevant context was retrieved.
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

    Args:
        query_text: Natural-language query text.

    Returns:
        The extracted sender text, or ``None`` when the query is unsupported.
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
    """Format a sender query into a display label.

    Args:
        sender_query: Sender text extracted from the query.

    Returns:
        A display-friendly sender label.
    """
    sender_query = (sender_query or "").strip()
    if "@" in sender_query:
        return sender_query
    return sender_query.title()


def _evaluate_multi_agent_graph(retrieved: list[dict], eval_detail: dict) -> dict:
    """Run the multi-agent policy decision graph over retrieved chunks.

    Args:
        retrieved: Retrieved chunks to evaluate.
        eval_detail: Policy evaluation detail record.

    Returns:
        The multi-agent decision graph output.
    """
    graph = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    return graph.evaluate(retrieved, eval_detail)

def orchestrator_function(context: df.DurableOrchestrationContext):
    """Run the durable orchestration for policy evaluation and response generation.

    Args:
        context: Durable Functions orchestration context for the current instance.

    Returns:
        The final orchestration payload describing allow, deny, or redaction outcomes.
    """
    input_payload = context.get_input()
    transaction_id = str(uuid.uuid4())
    start_time = datetime.utcnow()

    principal = input_payload.get("principal", {})
    odrl_policy = input_payload.get("odrl_policy", {})
    query_text = input_payload.get("query_text") or input_payload.get("query") or ""
    action = input_payload.get("action", "summarise")
    cosmos_endpoint = input_payload.get("cosmos_endpoint")
    database_name = input_payload.get("database", "policy_rag_db")
    cosmos_collection = input_payload.get("cosmos_collection", "EnronEmailVectorStore")

    pv = PolicyPurposeValidator(odrl_policy)
    allowed, eval_detail = pv.evaluate(principal.get("role",""), principal.get("declaredIntent",""), action)
    security_filters = pv.derive_security_filters(principal.get("role", ""), principal.get("declaredIntent", ""), action) if allowed else {}

    retrieved = []
    handled_count_query = False
    query_embedding = []
    decision_graph = {"decision": "Allow", "reasoning": {"signals": [], "tallies": {"deny": 0, "redact": 0, "allow": 0}}}
    count_sender = _extract_sender_from_count_query(query_text)
    if allowed and count_sender:
        retriever = ConflictAwareRetriever(cosmos_endpoint, database_name, cosmos_collection)
        retrieved_count = retriever.count_by_sender(count_sender, security_filters=security_filters)
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
        }
        handled_count_query = True
    elif allowed:
        # Retrieval is intentionally broad; policy enforcement happens after the RAG context is assembled.
        query_embedding = _build_query_embedding(query_text, input_payload.get("query_embedding", []))
        retriever = ConflictAwareRetriever(cosmos_endpoint, database_name, cosmos_collection)
        retrieved = retriever.retrieve(query_embedding, security_filters, top_k=10)
        decision_graph = _evaluate_multi_agent_graph(retrieved, eval_detail)

    if not allowed:
        generated = "Request denied due to policy restrictions."
        guard = {"status": "Pass", "action": "Release", "findings": []}
        enforcement_action_type = "Deny"
        final_payload = {"status": "denied", "reason": guard["findings"], "result": generated}
    elif handled_count_query:
        pass
    elif not retrieved:
        generated = "No relevant context was retrieved for this request."
        guard = {"status": "Pass", "action": "Release", "findings": []}
        enforcement_action_type = "Allow"
        final_payload = _build_no_results_payload()
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
            final_payload = {"status": "ok", "result": generated, "decisionGraph": decision_graph}

    end_time = datetime.utcnow()
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
        security_filters=security_filters,
        cosmos_collection=cosmos_collection,
        database_name=database_name,
        retrieved=retrieved,
        eval_detail=eval_detail,
        allowed=allowed,
        guard=guard,
        enforcement_action_type=enforcement_action_type,
        final_payload=final_payload,
        decision_graph=decision_graph,
    )
    # Include Cosmos connection info so StoreAuditEventActivity can persist the event
    audit_event["cosmos_endpoint"] = cosmos_endpoint
    audit_event["database"] = database_name
    store_result = yield context.call_activity("StoreAuditEventActivity", audit_event)
    if isinstance(store_result, dict) and store_result.get("status") != "ok":
        logging.warning("StoreAuditEventActivity returned non-ok status: %s", store_result)

    return final_payload

main = df.Orchestrator.create(orchestrator_function)
