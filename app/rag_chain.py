import os
from time import perf_counter
from typing import Any, Dict, List, Sequence

from azure.cosmos import CosmosClient
from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from sentence_transformers import SentenceTransformer
from typing_extensions import TypedDict

from app.audit_logger import AuditLogger
from app.policy_guard import (
    PolicyViolationError,
    evaluate_intent_against_odrl,
    redact_response_for_role,
    spokesperson_guardrail,
)

load_dotenv()

_EMBEDDING_MODEL = None


class RAGState(TypedDict):
    """Typed state passed between the LangGraph retrieval and answer steps."""

    question: str
    context: List[str]
    answer: str
    sources: List[str]
    user_roles: List[str]
    purpose: str
    action: str
    correlation_id: str
    user_id: str


def get_foundry_settings() -> Dict[str, str]:
    """Return the Microsoft Foundry configuration from environment variables.

    Returns:
        A dictionary containing the endpoint, API key, chat model, and embedding
        model settings.
    """
    return {
        "endpoint": os.getenv("FOUNDRY_ENDPOINT"),
        "api_key": os.getenv("FOUNDRY_API_KEY"),
        "chat_model": os.getenv("FOUNDRY_CHAT_MODEL", "gpt-4o-mini"),
        "embedding_model": os.getenv("FOUNDRY_EMBEDDING_MODEL", "text-embedding-3-small"),
    }


def get_cosmos_settings() -> Dict[str, str]:
    """Return the Cosmos DB configuration from environment variables.

    Returns:
        A dictionary containing the Cosmos endpoint, key, database, container,
        and embedding settings.
    """
    return {
        "endpoint": os.getenv("COSMOSDB_ENDPOINT"),
        "key": os.getenv("COSMOSDB_KEY"),
        "database": os.getenv("COSMOSDB_DATABASE"),
        "container": os.getenv("COSMOSDB_COLLECTION"),
        "embedding_model": os.getenv("EMBEDDING_MODEL"),
    }


def get_embedding_model() -> SentenceTransformer:
    """Return the shared sentence-transformer embedding model instance.

    Returns:
        The lazily initialized embedding model.
    """
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        _EMBEDDING_MODEL = SentenceTransformer(get_cosmos_settings()["embedding_model"])
    return _EMBEDDING_MODEL


def build_vector_store():
    """Create the configured Cosmos vector store client when credentials exist.

    Returns:
        The Cosmos DB container client.

    Raises:
        ValueError: If the required Cosmos configuration is missing.
    """
    if os.getenv("COSMOSDB_ENDPOINT") and os.getenv("COSMOSDB_KEY"):
        return get_cosmos_container()
    raise ValueError("COSMOSDB_ENDPOINT and COSMOSDB_KEY must be configured to use the Enron Cosmos vector store.")


def get_cosmos_container():
    """Create a Cosmos DB client bound to the configured database and container.

    Returns:
        A Cosmos DB container client.

    Raises:
        ValueError: If the Cosmos endpoint or key is not configured.
    """
    settings = get_cosmos_settings()
    if not settings["endpoint"] or not settings["key"]:
        raise ValueError("COSMOSDB_ENDPOINT and COSMOSDB_KEY must be configured to use the Enron Cosmos vector store.")

    client = CosmosClient(url=settings["endpoint"], credential=settings["key"])
    database = client.get_database_client(settings["database"])
    return database.get_container_client(settings["container"])


def embed_query(question: str) -> List[float]:
    """Encode a query into the embedding space used by Cosmos DB.

    Args:
        question: The raw natural-language query.

    Returns:
        The normalized embedding vector for the query.
    """
    return get_embedding_model().encode(question, normalize_embeddings=True).tolist()


def _normalize_roles(user_roles: Sequence[str] | None) -> List[str]:
    """Normalize caller security roles into the repository policy format.

    Args:
        user_roles: One or more role identifiers from the incoming request.

    Returns:
        A list of normalized role names.
    """
    if not user_roles:
        return []
    normalized: List[str] = []
    for role in user_roles:
        if role and str(role).strip():
            normalized.append(str(role).strip())
    return normalized


def retrieve_documents(
    question: str,
    user_roles: Sequence[str] | None = None,
    purpose: str | None = None,
    action: str | None = None,
    correlation_id: str | None = None,
    user_id: str | None = None,
    audit_logger: AuditLogger | None = None,
) -> List[Document]:
    """Retrieve relevant documents for the caller after ODRL validation and role filtering.

    Cosmos DB can reject complex nested-array predicates in some vector-query shapes,
    so we intentionally keep the query broad and apply the role enforcement in Python
    after retrieval. This preserves compatibility while still enforcing the document
    security metadata contract. Records with no `securityMetadata` remain eligible.
    """
    if user_roles is not None:
        evaluate_intent_against_odrl(question, user_roles, purpose=purpose, action=action)

    container = get_cosmos_container()
    query_vector = embed_query(question)
    allowed_roles = _normalize_roles(user_roles) or []

    query = """
        SELECT TOP 20
            c.id,
            c.subject,
            c["from"],
            c.to,
            c.date,
            c.body,
            c.securityMetadata,
            VectorDistance(c.vector, @embedding) AS similarity_score
        FROM c
        ORDER BY VectorDistance(c.vector, @embedding)
    """

    start_time = perf_counter()
    try:
        results = list(
            container.query_items(
                query=query,
                parameters=[{"name": "@embedding", "value": query_vector}],
                enable_cross_partition_query=True,
            )
        )
    except Exception:
        if audit_logger is not None:
            audit_logger.emit(
                step_name="ContextRetrieval",
                execution_status="ERROR",
                policy_metadata={
                    "roles": allowed_roles,
                    "purpose": purpose or "metadata_review",
                    "action": action or "retrieve",
                },
                telemetry={"queryLength": len(question), "latencyMs": int((perf_counter() - start_time) * 1000)},
                correlation_id=correlation_id,
                user_id=user_id,
                prompt_text=question,
                reason="Cosmos vector retrieval failed.",
                finalize=True,
            )
        raise

    documents: List[Document] = []
    for item in results:
        # The role filter is applied in Python because Cosmos rejects the nested
        # policy array predicate more reliably than the direct vector query.
        metadata = item.get("securityMetadata") or {}
        allowed_roles_for_item = metadata.get("policyRole") or []
        if isinstance(allowed_roles_for_item, str):
            allowed_roles_for_item = [allowed_roles_for_item]
        doc_roles = [str(role).lower() for role in allowed_roles_for_item]
        if allowed_roles and doc_roles and not any(role.lower() in doc_roles for role in [r.lower() for r in allowed_roles]):
            continue
        documents.append(
            Document(
                page_content=item.get("body") or item.get("subject") or "",
                metadata={
                    "source": item.get("id") or item.get("subject") or "enron-email",
                    "subject": item.get("subject"),
                    "from": item.get("from"),
                    "date": item.get("date"),
                    "similarity_score": item.get("similarity_score"),
                    "securityMetadata": metadata,
                },
            )
        )

    if audit_logger is not None:
        audit_logger.emit(
            step_name="ContextRetrieval",
            execution_status="ALLOWED",
            policy_metadata={
                "roles": allowed_roles,
                "purpose": purpose or "metadata_review",
                "action": action or "retrieve",
            },
            telemetry={
                "queryLength": len(question),
                "latencyMs": int((perf_counter() - start_time) * 1000),
                "documentMatchCount": len(documents),
            },
            correlation_id=correlation_id,
            user_id=user_id,
            prompt_text=question,
            document_ids=[doc.metadata.get("source") for doc in documents if doc.metadata.get("source")],
            finalize=False,
        )

    return documents


def retrieve_context(question: str, user_roles: Sequence[str] | None = None, purpose: str | None = None, action: str | None = None) -> List[str]:
    """Return just the page content for the role-safe retrieval results.

    Args:
        question: The user prompt.
        user_roles: Security roles for the caller.
        purpose: The ODRL purpose of the request.
        action: The requested action to validate.

    Returns:
        A list of retrieved document bodies that pass the policy filter.
    """
    docs = retrieve_documents(question, user_roles=user_roles, purpose=purpose, action=action)
    return [doc.page_content for doc in docs]


def build_rag_graph():
    """Build the LangGraph pipeline used to retrieve and answer the query."""
    settings = get_foundry_settings()

    llm = ChatOpenAI(
        model=settings["chat_model"],
        api_key=settings["api_key"],
        base_url=settings["endpoint"],
        temperature=0,
    )

    prompt = ChatPromptTemplate.from_template(
        """
You are a helpful assistant analyzing the Enron email corpus. Use only the retrieved email context to answer the user's question.

Context:
{context}

Question: {question}

Return a concise but complete answer and cite the relevant email metadata you used.
"""
    )

    def retrieve(state: RAGState) -> RAGState:
        """Retrieve the policy-safe document set for the current question."""
        user_roles = state.get("user_roles", [])
        purpose = state.get("purpose") or "metadata_review"
        action = state.get("action") or "retrieve"
        correlation_id = state.get("correlation_id")
        user_id = state.get("user_id")
        audit_logger = AuditLogger()
        evaluate_intent_against_odrl(state["question"], user_roles, purpose=purpose, action=action)
        docs = retrieve_documents(
            state["question"],
            user_roles=user_roles,
            purpose=purpose,
            action=action,
            correlation_id=correlation_id,
            user_id=user_id,
            audit_logger=audit_logger,
        )
        state["context"] = [doc.page_content for doc in docs]
        state["sources"] = [
            doc.metadata.get("source", "unknown")
            for doc in docs
        ]
        return state

    def answer(state: RAGState) -> RAGState:
        """Generate the final answer and apply the spokesperson guardrail."""
        chain = prompt | llm | StrOutputParser()
        answer = chain.invoke({
            "question": state["question"],
            "context": "\n\n".join(state["context"]),
        })
        audit_logger = AuditLogger()
        protected_answer = spokesperson_guardrail(
            state.get("context", []),
            answer,
            state.get("user_roles", []),
            purpose=state.get("purpose"),
        )
        was_redacted = protected_answer != answer
        audit_logger.emit(
            step_name="SpokespersonValidation",
            execution_status="REDACTED" if was_redacted else "ALLOWED",
            policy_metadata={
                "roles": state.get("user_roles", []),
                "purpose": state.get("purpose") or "metadata_review",
                "action": state.get("action") or "retrieve",
            },
            telemetry={
                "answerLength": len(answer),
                "redacted": was_redacted,
            },
            correlation_id=state.get("correlation_id"),
            user_id=state.get("user_id"),
            prompt_text=state["question"],
            response_text=answer,
            reason="Policy-aware spokesperson guardrail evaluated the generated answer.",
            finalize=False,
        )
        state["answer"] = protected_answer
        return state

    graph = StateGraph(RAGState)
    graph.add_node("retrieve", retrieve)
    graph.add_node("answer", answer)
    graph.add_edge("retrieve", "answer")
    graph.add_edge("answer", END)
    graph.set_entry_point("retrieve")
    return graph.compile()


def build_rag_chain():
    """Create and return the compiled RAG graph for execution.

    Returns:
        The compiled LangGraph pipeline instance.
    """
    return build_rag_graph()
