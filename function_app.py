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
    return orchestrator_function(context)


@app.activity_trigger(input_name="req")
def GenerateResponseActivity(req: dict) -> str:
    return generate_response_impl(req)


@app.activity_trigger(input_name="req")
def GenerateRedactedResponseActivity(req: dict) -> str:
    return generate_redacted_response_impl(req)


@app.activity_trigger(input_name="event")
def StoreAuditEventActivity(event: dict) -> dict:
    return store_audit_event_impl(event)


@app.route(route="orchestrators/start", methods=["POST"])
@app.durable_client_input(client_name="client")
async def start_orchestration(req: func.HttpRequest, client: df.DurableOrchestrationClient) -> func.HttpResponse:
    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse("Request body must be valid JSON.", status_code=400)

    instance_id = await client.start_new("orchestrator", None, payload)
    return client.create_check_status_response(req, instance_id)