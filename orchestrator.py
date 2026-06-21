import logging
import azure.durable_functions as df
from policy_validator import PolicyPurposeValidator
from retriever import ConflictAwareRetriever
from compliance_guard import compliance_guard
import uuid
from datetime import datetime

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
    else:
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
            guard = compliance_guard(generated, retrieved)

    if guard["status"] == "Fail":
        final_payload = {"status": "denied", "reason": guard["findings"]}
    else:
        final_payload = {"status": "ok", "result": generated}

    audit_event = {
        "transactionId": transaction_id,
        "timestamp": timestamp.isoformat(),
        "principal": principal,
        "policyEvaluation": {
            "matchedPolicyUid": eval_detail.get("matchedRules"),
            "ruleType": "odrl",
            "constraintSatisfaction": {"satisfied": eval_detail.get("satisfied")},
            "reasoningTrail": eval_detail.get("reasoning")
        },
        "enforcementAction": {
            "actionType": "Allow" if allowed else "Deny",
            "filteredNodesCount": len(retrieved),
            "complianceGuardStatus": guard["status"]
        }
    }
    # Include Cosmos connection info so StoreAuditEventActivity can persist the event
    audit_event["cosmos_endpoint"] = cosmos_endpoint
    audit_event["database"] = database_name
    store_result = yield context.call_activity("StoreAuditEventActivity", audit_event)
    if isinstance(store_result, dict) and store_result.get("status") != "ok":
        logging.warning("StoreAuditEventActivity returned non-ok status: %s", store_result)

    return final_payload

main = df.Orchestrator.create(orchestrator_function)
