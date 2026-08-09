import os

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
        The orchestration result returned by the shared orchestrator function.
    """
    return orchestrator_function(context)


@app.activity_trigger(input_name="req")
def GenerateResponseActivity(req: dict) -> str:
    """Generate a policy-aware response for the given activity payload.

    Args:
        req: Activity input payload containing query and retrieval context.

    Returns:
        The generated response text.
    """
    return generate_response_impl(req)


@app.activity_trigger(input_name="req")
def GenerateRedactedResponseActivity(req: dict) -> str:
    """Generate a redacted policy-aware response for the given payload.

    Args:
        req: Activity input payload containing query and retrieval context.

    Returns:
        The generated redacted response text.
    """
    return generate_redacted_response_impl(req)


@app.activity_trigger(input_name="event")
def StoreAuditEventActivity(event: dict) -> dict:
    """Persist an audit event for the current orchestration.

    Args:
        event: Audit event payload to store in Cosmos DB.

    Returns:
        A status dictionary describing the storage result.
    """
    return store_audit_event_impl(event)


@app.route(route="orchestrators/start", methods=["POST"])
@app.durable_client_input(client_name="client")
async def start_orchestration(req: func.HttpRequest, client: df.DurableOrchestrationClient) -> func.HttpResponse:
    """Start a new orchestration instance from an HTTP request.

    Args:
        req: Incoming HTTP request containing the orchestration payload.
        client: Durable orchestration client used to start the instance.

    Returns:
        The standard Durable Functions status response.
    """
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Request body must be valid JSON.", status_code=400)
    payload["cosmos_endpoint"] = os.environ["COSMOS_DB_ENDPOINT"]
    payload["database"] = os.environ["COSMOS_DB_DATABASE"]
    payload["cosmos_key"] = os.environ.get("COSMOS_KEY")

    instance_id = await client.start_new("orchestrator", None, payload)
    return client.create_check_status_response(req, instance_id)
