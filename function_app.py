"""Azure Functions entry point for the PolicyAwareRAG Durable orchestration.

This module contains the public HTTP trigger used to start orchestrations and the
activity triggers that delegate to the implementation functions in
``activities.py``. Each trigger is intentionally thin: it validates input and
forwards execution to the orchestrator or implementation layer without changing
application behavior.
"""

import azure.durable_functions as df
import azure.functions as func

from activities import (
    GenerateRedactedResponseActivity as generate_redacted_response_impl,
    GenerateResponseActivity as generate_response_impl,
    StoreAuditEventActivity as store_audit_event_impl,
)
from orchestrator import orchestrator_function


app = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)


@app.orchestration_trigger(context_name="context")
def orchestrator(context: df.DurableOrchestrationContext):
    """Run the durable orchestration entry point.

    Args:
        context: Durable Functions orchestration context for the current instance.

    Returns:
        object: The orchestration result returned by the shared orchestrator function.
    """
    return orchestrator_function(context)


@app.activity_trigger(input_name="req")
def GenerateResponseActivity(req: dict) -> str:
    """Generate a policy-aware response from the activity payload.

    Args:
        req: Activity payload containing the query, principal, policy evaluation,
            and retrieved context.

    Returns:
        str: Generated response text.
    """
    return generate_response_impl(req)


@app.activity_trigger(input_name="req")
def GenerateRedactedResponseActivity(req: dict) -> str:
    """Generate a safely redacted response from the activity payload.

    Args:
        req: Activity payload containing the query and retrieved context for a
            redaction-restricted response.

    Returns:
        str: Redacted response text.
    """
    return generate_redacted_response_impl(req)


@app.activity_trigger(input_name="event")
def StoreAuditEventActivity(event: dict) -> dict:
    """Persist an audit event for the active orchestration.

    Args:
        event: Audit event payload to store in Cosmos DB.

    Returns:
        dict: Status dictionary describing the storage result.
    """
    return store_audit_event_impl(event)


@app.route(route="orchestrators/start", methods=["POST"])
@app.durable_client_input(client_name="client")
async def start_orchestration(req: func.HttpRequest, client: df.DurableOrchestrationClient) -> func.HttpResponse:
    """Start a new orchestration instance from an HTTP request.

    The HTTP trigger validates the incoming JSON payload and forwards it to the
    durable orchestrator. It ensures the required top-level request fields are set
    before starting the instance.

    Args:
        req: Incoming HTTP request containing the orchestration payload.
        client: Durable orchestration client used to create the new instance.

    Returns:
        func.HttpResponse: Standard Durable Functions status response.
    """
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Request body must be valid JSON.", status_code=400)

    if not isinstance(payload, dict):
        return func.HttpResponse("Request body must be a JSON object.", status_code=400)

    if not payload:
        return func.HttpResponse("Request body must not be empty.", status_code=400)

    payload.setdefault("principal", {})
    payload.setdefault("odrl_policy", {})
    payload.setdefault("query_text", "")
    payload.setdefault("action", "summarise")

    instance_id = await client.start_new("orchestrator", None, payload)
    return client.create_check_status_response(req, instance_id)
