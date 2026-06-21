import logging
import azure.durable_functions as df
from policy_validator import PolicyPurposeValidator
from retriever import ConflictAwareRetriever
from compliance_guard import compliance_guard
import uuid
from datetime import datetime


def _format_reasoning_trail(reasoning: list[str]) -> str:
    if not reasoning:
        return ""
    return "; ".join(reasoning)


def _map_guard_status(guard_status: str, outcome_status: str, enforcement_action_type: str) -> str:
    if enforcement_action_type == "Partial_Redaction":
        return "Sanitized"
    if outcome_status == "denied":
        return "Blocked"
    if guard_status == "Fail":
        return "Sanitized"
    return "Passed"


def build_audit_event(
    transaction_id: str,
    timestamp: datetime,
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
) -> dict:
    matched_rules = eval_detail.get("matchedRules") or []
    matched_policy_uid = matched_rules[0] if matched_rules else odrl_policy.get("uid", "")
    outcome_status = final_payload.get("status", "")

    return {
        "id": transaction_id,
        "transactionId": transaction_id,
        "timestamp": timestamp.isoformat(),
        "principal": {
            "userId": principal.get("userId", ""),
            "role": principal.get("role", ""),
            "declaredIntent": principal.get("declaredIntent", ""),
        },
        "request": {
            "queryText": query_text,
            "queryEmbedding": query_embedding,
            "action": action,
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
        "retrieved": retrieved,
        "outcome": final_payload,
    }

def orchestrator_function(context: df.DurableOrchestrationContext):
    """Run the durable orchestration for policy evaluation and response generation.

    Args:
        context: Durable Functions orchestration context for the current instance.

    Returns:
        The final orchestration payload describing allow, deny, or redaction outcomes.
    """
    input_payload = context.get_input()
    transaction_id = str(uuid.uuid4())
    timestamp = datetime.utcnow()

    principal = input_payload.get("principal", {})
    odrl_policy = input_payload.get("odrl_policy", {})
    query_embedding = input_payload.get("query_embedding", [])
    query_text = input_payload.get("query_text") or input_payload.get("query") or ""
    action = input_payload.get("action", "summarise")
    cosmos_endpoint = input_payload.get("cosmos_endpoint")
    database_name = input_payload.get("database", "policy_rag_db")
    cosmos_collection = input_payload.get("cosmos_collection", "VectorDatabase")

    pv = PolicyPurposeValidator(odrl_policy)
    allowed, eval_detail = pv.evaluate(principal.get("role",""), principal.get("declaredIntent",""), action)

    retrieved = []
    if allowed:
        security_filters = {"allowedRole": principal.get("role")}
        retriever = ConflictAwareRetriever(cosmos_endpoint, database_name, cosmos_collection)
        retrieved = retriever.retrieve(query_embedding, security_filters, top_k=10)

    if not allowed:
        generated = "Request denied due to policy restrictions."
        guard = {"status": "Pass", "action": "Release", "findings": []}
        enforcement_action_type = "Deny"
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
        final_payload = {"status": "denied", "reason": guard["findings"]}
    else:
        final_payload = {"status": "ok", "result": generated}

    audit_event = build_audit_event(
        transaction_id=transaction_id,
        timestamp=timestamp,
        principal=principal,
        odrl_policy=odrl_policy,
        query_text=query_text,
        query_embedding=query_embedding,
        action=action,
        cosmos_collection=cosmos_collection,
        database_name=database_name,
        retrieved=retrieved,
        eval_detail=eval_detail,
        allowed=allowed,
        guard=guard,
        enforcement_action_type=enforcement_action_type,
        final_payload=final_payload,
    )
    # Include Cosmos connection info so StoreAuditEventActivity can persist the event
    audit_event["cosmos_endpoint"] = cosmos_endpoint
    audit_event["database"] = database_name
    store_result = yield context.call_activity("StoreAuditEventActivity", audit_event)
    if isinstance(store_result, dict) and store_result.get("status") != "ok":
        logging.warning("StoreAuditEventActivity returned non-ok status: %s", store_result)

    return final_payload

main = df.Orchestrator.create(orchestrator_function)
