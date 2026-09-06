"""Azure Function entry points for the policy-aware RAG app."""

import json
import logging
from time import perf_counter
import uuid

import azure.functions as func

from app.audit_logger import AuditLogger
from app.policy_guard import PolicyViolationError, evaluate_intent_against_odrl
from app.rag_chain import build_rag_chain

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)


@app.route(route="rag", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def rag_http(req: func.HttpRequest) -> func.HttpResponse:
    """Handle a post request to the policy-aware RAG endpoint.

    Args:
        req: The incoming Azure Function HTTP request.

    Returns:
        A JSON HTTP response containing the generated answer, sources, and
        policy metadata, or an error response when validation fails.
    """
    logging.info("RAG HTTP trigger invoked.")

    try:
        payload = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Request body must be valid JSON."}),
            mimetype="application/json",
            status_code=400,
        )

    question = (payload or {}).get("question")
    if not question or not isinstance(question, str) or not question.strip():
        return func.HttpResponse(
            json.dumps({"error": "Field 'question' is required."}),
            mimetype="application/json",
            status_code=400,
        )

    user_roles = (payload or {}).get("userRoles") or (payload or {}).get("roles") or []
    purpose = (payload or {}).get("purpose")
    action = (payload or {}).get("action") or "retrieve"
    user_id = (payload or {}).get("userId") or (payload or {}).get("user_id") or "anonymous"
    correlation_id = (payload or {}).get("correlationId") or str(uuid.uuid4())
    audit_logger = AuditLogger()
    intent_start = perf_counter()

    if isinstance(user_roles, str):
        user_roles = [user_roles]
    if not isinstance(user_roles, list):
        user_roles = []

    try:
        policy_allowed = evaluate_intent_against_odrl(question, user_roles, purpose=purpose, action=action)
        if not policy_allowed:
            raise PolicyViolationError("Policy denial: intent evaluation returned false.")

        audit_logger.emit(
            step_name="IntentValidation",
            execution_status="ALLOWED",
            policy_metadata={
                "requestType": "rag",
                "roles": user_roles,
                "purpose": purpose or "metadata_review",
                "action": action,
            },
            telemetry={
                "queryLength": len(question),
                "latencyMs": round((perf_counter() - intent_start) * 1000, 3),
            },
            correlation_id=correlation_id,
            user_id=user_id,
            prompt_text=question,
            reason="Intent validated successfully.",
            finalize=False,
        )

        chain = build_rag_chain(audit_logger=audit_logger)
        result = chain.invoke({
            "question": question,
            "user_roles": user_roles,
            "purpose": purpose or "metadata_review",
            "action": action,
            "correlation_id": correlation_id,
            "user_id": user_id,
        })

        final_answer = result.get("answer", "")
        output_start = perf_counter()
        final_status = "REDACTED" if final_answer != result.get("answer", "") else "ALLOWED"
        audit_logger.emit(
            step_name="OutputRedaction",
            execution_status=final_status,
            policy_metadata={
                "roles": user_roles,
                "purpose": purpose or "metadata_review",
                "action": action,
            },
            telemetry={
                "documentMatchCount": len(result.get("sources", [])),
                "responseLength": len(final_answer),
                "latencyMs": round((perf_counter() - output_start) * 1000, 3),
            },
            correlation_id=correlation_id,
            user_id=user_id,
            response_text=final_answer,
            reason="Final response delivered to caller.",
            finalize=True,
        )

        return func.HttpResponse(
            json.dumps({
                "question": question,
                "answer": final_answer,
                "sources": result.get("sources", []),
                "userRoles": user_roles,
                "purpose": purpose or "metadata_review",
                "correlationId": correlation_id,
            }),
            mimetype="application/json",
            status_code=200,
        )
    except PolicyViolationError as exc:
        logging.warning("Policy denial triggered: %s", exc)
        audit_logger.emit(
            step_name="IntentValidation",
            execution_status="DENIED",
            policy_metadata={
                "requestType": "rag",
                "roles": user_roles,
                "purpose": purpose or "metadata_review",
                "action": action,
            },
            telemetry={
                "queryLength": len(question),
                "latencyMs": round((perf_counter() - intent_start) * 1000, 3),
            },
            correlation_id=correlation_id,
            user_id=user_id,
            prompt_text=question,
            reason=str(exc),
            finalize=True,
        )
        return func.HttpResponse(
            json.dumps({"error": "Policy denial: the request is not permitted by the active ODRL policy.", "policyDenied": True, "correlationId": correlation_id}),
            mimetype="application/json",
            status_code=403,
        )
    except Exception as exc:  # pragma: no cover - function boundary
        logging.exception("RAG request failed.")
        audit_logger.emit(
            step_name="IntentValidation",
            execution_status="ERROR",
            policy_metadata={
                "requestType": "rag",
                "roles": user_roles,
                "purpose": purpose or "metadata_review",
                "action": action,
            },
            telemetry={
                "queryLength": len(question),
                "latencyMs": round((perf_counter() - intent_start) * 1000, 3),
            },
            correlation_id=correlation_id,
            user_id=user_id,
            prompt_text=question,
            reason="Request failed during execution.",
            finalize=True,
        )
        return func.HttpResponse(
            json.dumps({"error": "The request could not be completed due to an internal error.", "correlationId": correlation_id}),
            mimetype="application/json",
            status_code=500,
        )


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Return a simple health response for the app.

    Args:
        req: The incoming Azure Function HTTP request.

    Returns:
        A successful JSON response indicating the service is running.
    """
    return func.HttpResponse(
        json.dumps({"status": "ok"}),
        mimetype="application/json",
        status_code=200,
    )
