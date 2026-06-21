import logging
from azure.identity import DefaultAzureCredential
from azure.cosmos import CosmosClient

def GenerateResponseActivity(req: dict) -> str:
    """Generate a model response for the retrieved request context.

    Args:
        req: Activity input containing the query context and retrieved chunks.

    Returns:
        A placeholder response string until the Azure OpenAI integration is wired up.
    """
    # Placeholder activity: integrate with Azure AI / OpenAI endpoint here
    return "[LLM response placeholder]"

def GenerateRedactedResponseActivity(req: dict) -> str:
    """Build a redacted response from the retrieved chunks.

    Args:
        req: Activity input containing a ``retrieved`` list of chunk dictionaries.

    Returns:
        A newline-delimited string containing the first 200 characters of each chunk.
    """
    retrieved = req.get("retrieved", [])
    parts = []
    for c in retrieved:
        parts.append(c.get("content", "")[:200])
    return "\n---\n".join(parts)

def StoreAuditEventActivity(event: dict) -> dict:
    """Persist an audit event to the Cosmos DB audit container.

    Args:
        event: Audit event payload containing Cosmos endpoint and event fields.

    Returns:
        A status dictionary indicating success, missing configuration, or error details.
    """
    try:
        credential = DefaultAzureCredential()
        endpoint = event.get("cosmos_endpoint")
        if not endpoint:
            return {"status": "missing_endpoint"}
        client = CosmosClient(url=endpoint, credential=credential)
        db = client.get_database_client(event.get("database", "policy_rag_db"))
        container = db.get_container_client("AuditStorage")
        event_doc = event.copy()
        container.create_item(body=event_doc)
        return {"status": "ok"}
    except Exception as e:
        logging.exception("failed to store audit event")
        return {"status": "error", "error": str(e)}
