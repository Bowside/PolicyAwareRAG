"""LangGraph orchestration for policy-aware retrieval and answer generation.

The module embeds queries, retrieves policy-filtered documents from Cosmos DB,
generates an answer with Microsoft Foundry, and records pipeline telemetry.
"""

import json
import os
import re
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
    normalize_policy_role,
    redact_response_for_role,
    requires_semantic_policy_review,
    spokesperson_guardrail,
)

load_dotenv()

_EMBEDDING_MODEL = None


def _estimate_tokens(value: Any) -> int:
    """Estimate tokens from text using the evaluation harness heuristic.

    Args:
        value: Text whose approximate token count should be calculated.

    Returns:
        An estimated token count, or zero for empty input.
    """
    text = str(value or "").strip()
    if not text:
        return 0
    return max(1, round(len(text) / 4.0))


class RAGState(TypedDict):
    """Typed state passed between the LangGraph retrieval and answer steps."""

    question: str
    context: List[str]
    answer: str
    base_answer: str
    sources: List[str]
    user_roles: List[str]
    purpose: str
    action: str
    correlation_id: str
    user_id: str


def get_foundry_settings() -> Dict[str, Any]:
    """Return the Microsoft Foundry configuration from environment variables.

    Returns:
        A dictionary containing the endpoint, API key, chat model, and embedding
        model and temperature settings.
    """
    return {
        "endpoint": os.getenv("FOUNDRY_ENDPOINT"),
        "api_key": os.getenv("FOUNDRY_API_KEY"),
        "chat_model": os.getenv("FOUNDRY_CHAT_MODEL", "gpt-4o-mini"),
        "embedding_model": os.getenv("FOUNDRY_EMBEDDING_MODEL", "text-embedding-3-small"),
        "temperature": float(os.getenv("FOUNDRY_TEMPERATURE", "1.0")),
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


def _rerank_documents(question: str, documents: List[Document], limit: int = 10) -> List[Document]:
    """Rerank vector results with lightweight query-term overlap.

    Args:
        question: User query used to identify salient terms.
        documents: Vector-retrieved documents in similarity order.
        limit: Maximum number of documents returned to generation.

    Returns:
        A bounded list ordered by lexical overlap, with vector order as a tie-breaker.
    """
    query_terms = {term for term in re.findall(r"[a-z0-9]+", question.lower()) if len(term) > 2}
    scored_documents = []
    for position, document in enumerate(documents):
        text = " ".join(
            str(document.metadata.get(field) or "")
            for field in ("subject", "from", "date")
        ) + " " + document.page_content
        document_terms = set(re.findall(r"[a-z0-9]+", text.lower()))
        overlap = len(query_terms & document_terms)
        scored_documents.append((overlap, -position, document))
    scored_documents.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [document for _, _, document in scored_documents[:limit]]


def _format_context_document(document: Document) -> str:
    """Format one retrieved document with stable source metadata.

    Args:
        document: Retrieved document with source metadata and body text.

    Returns:
        A labeled evidence block for the answer prompt.
    """
    metadata = document.metadata
    return "\n".join(
        [
            f"[Source: {metadata.get('source', 'unknown')}]",
            f"Subject: {metadata.get('subject') or 'Not available'}",
            f"From: {metadata.get('from') or 'Not available'}",
            f"Date: {metadata.get('date') or 'Not available'}",
            f"Body: {document.page_content}",
        ]
    )


def retrieve_documents(
    question: str,
    user_roles: Sequence[str] | None = None,
    purpose: str | None = None,
    action: str | None = None,
    correlation_id: str | None = None,
    user_id: str | None = None,
    audit_logger: AuditLogger | None = None,
) -> List[Document]:
    """Retrieve relevant documents after ODRL validation and role filtering.

    Args:
        question: Natural-language request used for retrieval.
        user_roles: Caller roles used for policy validation and filtering.
        purpose: Declared purpose of the request.
        action: Declared action for the request.
        correlation_id: Request identifier used for audit aggregation.
        user_id: Caller identifier used for audit pseudonymization.
        audit_logger: Optional logger for retrieval telemetry.

    Returns:
        Documents that match retrieval and role-filtering requirements.

    Raises:
        PolicyViolationError: If the request is not authorized.
        ValueError: If required Cosmos or embedding configuration is missing.
        Exception: If the vector query fails.

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
        SELECT TOP 25
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
                telemetry={"queryLength": len(question), "latencyMs": round((perf_counter() - start_time) * 1000, 3)},
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

    documents = _rerank_documents(question, documents)

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
                "latencyMs": round((perf_counter() - start_time) * 1000, 3),
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


def build_rag_graph(audit_logger: AuditLogger | None = None):
    """Build the LangGraph pipeline used to retrieve and answer a query.

    Args:
        audit_logger: Optional request-scoped logger shared by pipeline nodes.

    Returns:
        A compiled LangGraph workflow.
    """
    settings = get_foundry_settings()

    llm = ChatOpenAI(
        model=settings["chat_model"],
        api_key=settings["api_key"],
        base_url=settings["endpoint"],
        temperature=settings["temperature"],
    )

    prompt = ChatPromptTemplate.from_template(
        """
You are a careful evidence-grounded assistant analyzing the Enron email corpus.

Use only facts directly supported by the retrieved context. For every factual
claim, cite the supporting source ID in square brackets. Do not infer names,
dates, causes, or relationships that are not stated in the context. If the provided 
context does not contain enough information to answer the question, respond with 
exactly: 'Insufficient information in the provided context.'. Treat email headers
(From, To, Date, Subject) as factual context. Do not assume nicknames, aliases,
or full names unless explicitly mapped in the text. Prefer a
short, qualified answer over unsupported detail.

Context:
{context}

Question: {question}

Return a concise answer with the relevant supported findings and source IDs.
"""
    )

    def retrieve(state: RAGState) -> RAGState:
        """Retrieve the policy-safe document set for the current question.

        Args:
            state: Current RAG graph state containing the request details.

        Returns:
            The updated state with retrieved context and source identifiers.
        """
        user_roles = state.get("user_roles", [])
        purpose = state.get("purpose") or "metadata_review"
        action = state.get("action") or "retrieve"
        correlation_id = state.get("correlation_id")
        user_id = state.get("user_id")
        request_audit_logger = audit_logger or AuditLogger()
        evaluate_intent_against_odrl(state["question"], user_roles, purpose=purpose, action=action)
        docs = retrieve_documents(
            state["question"],
            user_roles=user_roles,
            purpose=purpose,
            action=action,
            correlation_id=correlation_id,
            user_id=user_id,
            audit_logger=request_audit_logger,
        )
        state["context"] = [_format_context_document(doc) for doc in docs]
        state["sources"] = [
            doc.metadata.get("source", "unknown")
            for doc in docs
        ]
        return state

    def answer(state: RAGState) -> RAGState:
        """Generate the final answer and apply the spokesperson guardrail.

        Args:
            state: Current RAG graph state containing retrieved context.

        Returns:
            The updated state containing the protected answer.
        """
        generation_start = perf_counter()
        chain = prompt | llm | StrOutputParser()
        answer = chain.invoke({
            "question": state["question"],
            "context": "\n\n".join(state["context"]),
        })
        request_audit_logger = audit_logger or AuditLogger()
        request_audit_logger.emit(
            step_name="BaseRAG",
            execution_status="ALLOWED",
            policy_metadata={
                "roles": state.get("user_roles", []),
                "purpose": state.get("purpose") or "metadata_review",
                "action": state.get("action") or "retrieve",
            },
            telemetry={
                "answerLength": len(answer),
                "answerTokens": _estimate_tokens(answer),
                "latencyMs": round((perf_counter() - generation_start) * 1000, 3),
            },
            correlation_id=state.get("correlation_id"),
            user_id=state.get("user_id"),
            prompt_text=state["question"],
            response_text=answer,
            reason="Base RAG answer generated from retrieved context.",
            finalize=False,
        )
        validation_start = perf_counter()
        protected_answer = spokesperson_guardrail(
            state.get("context", []),
            answer,
            state.get("user_roles", []),
            purpose=state.get("purpose"),
        )
        was_redacted = protected_answer != answer
        request_audit_logger.emit(
            step_name="SpokespersonValidation",
            execution_status="REDACTED" if was_redacted else "ALLOWED",
            policy_metadata={
                "roles": state.get("user_roles", []),
                "purpose": state.get("purpose") or "metadata_review",
                "action": state.get("action") or "retrieve",
            },
            telemetry={
                "answerLength": len(answer),
                "answerTokens": _estimate_tokens(protected_answer),
                "inputAnswerTokens": _estimate_tokens(answer),
                "outputAnswerTokens": _estimate_tokens(protected_answer),
                "spokespersonTokens": _estimate_tokens(answer) + _estimate_tokens(protected_answer),
                "redacted": was_redacted,
                "latencyMs": round((perf_counter() - validation_start) * 1000, 3),
            },
            correlation_id=state.get("correlation_id"),
            user_id=state.get("user_id"),
            prompt_text=state["question"],
            response_text=answer,
            reason="Policy-aware spokesperson guardrail evaluated the generated answer.",
            finalize=False,
        )
        semantic_review_required = requires_semantic_policy_review(
            state.get("user_roles", []),
            purpose=state.get("purpose"),
            action=state.get("action"),
            intent=state.get("question"),
        )
        reviewed_answer = protected_answer
        if semantic_review_required:
            semantic_review_start = perf_counter()
            semantic_review_prompt = ChatPromptTemplate.from_template(
                """
You are the final policy-aware spokesperson. The deterministic authorization
and redaction checks have already passed. Review the protected answer and
return JSON with exactly three fields: "decision" ("ALLOW" or "DENY"),
"reason" (a short explanation), and "answer" (the final response text).

For the business-observer role, the final answer MUST contain no personal
names. Remove or replace every person's name, including names in prose,
headings, quotations, and citations. Use [REDACTED_NAME] when needed, while
preserving the supported meaning and source IDs. Do not reject an answer just
because it contains business facts or sensitive-looking text; transform it to
remove personal names. Return DENY only if the answer cannot be safely
rewritten under the stated policy. For other roles, preserve the protected
answer unless an explicit policy violation is present. Do not judge answer
relevance or completeness.

Role: {role}
Purpose: {purpose}
Action: {action}
Question: {question}
Protected answer:
{answer}
"""
            )
            review_chain = semantic_review_prompt | llm | StrOutputParser()
            review_raw = ""
            review_result: dict[str, Any] = {}
            review_error: PolicyViolationError | None = None
            normalized_roles = [
                normalize_policy_role(role)
                for role in state.get("user_roles", [])
                if normalize_policy_role(role)
            ]
            spokesperson_role = (
                "business-observer"
                if "business-observer" in normalized_roles
                else (normalized_roles[0] if normalized_roles else "")
            )
            review_prompt_text = "\n".join(
                [
                    "Role: " + spokesperson_role,
                    "Purpose: " + str(state.get("purpose") or "metadata_review"),
                    "Action: " + str(state.get("action") or "retrieve"),
                    "Question: " + state["question"],
                    "Protected answer:",
                    protected_answer,
                ]
            )
            try:
                review_raw = review_chain.invoke({
                    "role": spokesperson_role,
                    "purpose": state.get("purpose") or "metadata_review",
                    "action": state.get("action") or "retrieve",
                    "question": state["question"],
                    "answer": protected_answer,
                })
                parsed_review = json.loads(review_raw)
                if not isinstance(parsed_review, dict):
                    raise TypeError("semantic review output was not an object")
                review_result = parsed_review
            except (TypeError, json.JSONDecodeError) as exc:
                review_error = PolicyViolationError("Policy denial: semantic policy review returned invalid output.")
                review_error.__cause__ = exc
            except Exception as exc:
                review_error = PolicyViolationError("Policy denial: semantic policy review failed.")
                review_error.__cause__ = exc

            decision = str(review_result.get("decision", "")).strip().upper()
            reviewed_answer = str(review_result.get("answer") or "").strip()
            if spokesperson_role == "business-observer" and not reviewed_answer:
                review_error = PolicyViolationError(
                    "Policy denial: spokesperson returned no sanitized answer."
                )
            if spokesperson_role != "business-observer":
                reviewed_answer = protected_answer
            semantic_review_latency = round((perf_counter() - semantic_review_start) * 1000, 3)
            review_status = "ALLOWED" if review_error is None and reviewed_answer else "DENIED"
            request_audit_logger.emit(
                step_name="SemanticPolicyReview",
                execution_status=review_status,
                policy_metadata={
                    "roles": state.get("user_roles", []),
                    "purpose": state.get("purpose") or "metadata_review",
                    "action": state.get("action") or "retrieve",
                    "reviewRequired": True,
                },
                telemetry={
                    "answerLength": len(reviewed_answer),
                    "promptTokens": _estimate_tokens(review_prompt_text),
                    "completionTokens": _estimate_tokens(review_raw),
                    "totalTokens": _estimate_tokens(review_prompt_text) + _estimate_tokens(review_raw),
                    "inputAnswerTokens": _estimate_tokens(protected_answer),
                    "outputAnswerTokens": _estimate_tokens(review_raw),
                    "reviewDecision": decision,
                    "latencyMs": semantic_review_latency,
                },
                correlation_id=state.get("correlation_id"),
                user_id=state.get("user_id"),
                prompt_text=state["question"],
                response_text=reviewed_answer,
                reason=str(review_result.get("reason") or "Semantic policy review completed."),
                finalize=False,
            )
            if review_error is not None:
                raise review_error
            if spokesperson_role == "business-observer" and not reviewed_answer:
                raise PolicyViolationError(
                    "Policy denial: spokesperson returned no sanitized answer."
                )
            # Deterministic authorization remains authoritative. For roles other
            # than business-observer, the semantic model cannot turn an answer-
            # quality concern into a policy denial.
        state["answer"] = reviewed_answer
        state["base_answer"] = answer
        return state

    graph = StateGraph(RAGState)
    graph.add_node("retrieve", retrieve)
    graph.add_node("generate_answer", answer)
    graph.add_edge("retrieve", "generate_answer")
    graph.add_edge("generate_answer", END)
    graph.set_entry_point("retrieve")
    return graph.compile()


def build_rag_chain(audit_logger: AuditLogger | None = None):
    """Create and return the compiled RAG graph for execution.

    Returns:
        The compiled LangGraph pipeline instance.
    """
    return build_rag_graph(audit_logger=audit_logger)
