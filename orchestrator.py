import logging
import azure.durable_functions as df
from policy_validator import PolicyPurposeValidator
from retriever import ConflictAwareRetriever
from graph_state import MultiAgentGraph, restrictive_agent, permissive_agent
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

    mag = MultiAgentGraph(agents=[restrictive_agent, permissive_agent])
    decision_result = mag.evaluate(retrieved, {"satisfied": allowed, **eval_detail})

    generated = ""
    if decision_result["decision"] == "Allow":
        generated = yield context.call_activity("GenerateResponseActivity", {"query_embedding": query_embedding, "retrieved": retrieved})
    elif decision_result["decision"] == "Partial_Redaction":
        generated = yield context.call_activity("GenerateRedactedResponseActivity", {"retrieved": retrieved})
    else:
        generated = "Request denied due to policy restrictions."

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
            "actionType": decision_result["decision"],
            "filteredNodesCount": len(retrieved),
            "complianceGuardStatus": guard["status"]
        }
    }
    yield context.call_activity("StoreAuditEventActivity", audit_event)

    return final_payload

main = df.Orchestrator.create(orchestrator_function)
