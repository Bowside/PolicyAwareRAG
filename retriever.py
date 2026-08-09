import os
import re
from typing import Any, Dict, List, Optional

from azure.cosmos import CosmosClient

class ConflictAwareRetriever:
    def __init__(self, cosmos_endpoint: str, database_name: str, container_name: str, cosmos_key: Optional[str] = None):
        """Create a retriever backed by a Cosmos DB container.

        Args:
            cosmos_endpoint: Cosmos DB account endpoint URI.
            database_name: Database name containing the vector container.
            container_name: Container name used for retrieval.
            cosmos_key: Cosmos DB account key. Falls back to the COSMOS_KEY environment variable.
        """
        credential = cosmos_key or os.environ.get("COSMOS_KEY")
        if not credential:
            raise ValueError("COSMOS_KEY must be provided to initialize the Cosmos client.")

        self.client = CosmosClient(url=cosmos_endpoint, credential=credential)
        self.db = self.client.get_database_client(database_name)
        self.container = self.db.get_container_client(container_name)

    def retrieve(self, query_embedding: List[float], security_filters: Dict[str, Any], top_k: int = 10) -> List[Dict]:
        """Retrieve the highest-scoring chunks that satisfy the security filters.

        Uses Cosmos DB's native VectorDistance function for similarity scoring.

        Args:
            query_embedding: Query embedding vector used for similarity ranking.
            security_filters: Metadata filters applied to the Cosmos query.
            top_k: Maximum number of ranked items to return.

        Returns:
            A list of matching chunk dictionaries ordered by descending similarity.
        """
        # Build WHERE clause for security filters
        where_clauses = []
        params = [{"name": "@query_vector", "value": query_embedding}]
        
        idx = 0
        for k, v in security_filters.items():
            idx += 1
            param_name = f"@p{idx}"
            where_clauses.append(f"c.securityMetadata.{k} = {param_name}")
            params.append({"name": param_name, "value": v})
        
        where_sql = " AND ".join(where_clauses) if where_clauses else ""
        where_clause = f"WHERE {where_sql}" if where_sql else ""
        
        # Use Cosmos DB's native VectorDistance for similarity scoring
        query = f"""
            SELECT TOP {top_k} c.subject, c["from"], c.to, c.date, c.body,
            VectorDistance(c.vector, @query_vector) AS similarity_score
            FROM c
            {where_clause}
            ORDER BY VectorDistance(c.vector, @query_vector)
        """        
        try:
            items = list(self.container.query_items(
                query=query, 
                parameters=params, 
                enable_cross_partition_query=True
            ))
            return items
        except Exception as e:
            import logging
            logging.error(f"Cosmos DB vector search failed: {e}")
            logging.debug(f"Query: {query}")
            logging.debug(f"Parameters count: {len(params)}")
            raise

    def count_by_sender(self, sender_query: str, security_filters: Optional[Dict[str, Any]] = None) -> int:
        """Count documents whose sender field matches the provided sender text.

        Uses a case-insensitive containment check so human names such as
        "Fran Fagan" can match sender values like "fran.fagan@enron.com".
        """
        normalized_sender = re.sub(r"\s+", " ", (sender_query or "").strip())
        if not normalized_sender:
            return 0

        sender_terms = [term for term in re.split(r"[\s,]+", normalized_sender) if term]
        sender_name_match = normalized_sender.lower()
        sender_variants = []

        def _add_variant(candidate: str) -> None:
            candidate = candidate.strip().lower()
            if candidate and candidate not in sender_variants:
                sender_variants.append(candidate)

        if len(sender_terms) >= 2:
            _add_variant(".".join(sender_terms[:2]))

        _add_variant(sender_name_match)

        if sender_terms:
            first_token = sender_terms[0].lower()
            if first_token.endswith("s") and len(first_token) > 3:
                singular_terms = [first_token[:-1]] + [term.lower() for term in sender_terms[1:2]]
                _add_variant(".".join(singular_terms))
                _add_variant(" ".join([singular_terms[0]] + [term.lower() for term in sender_terms[1:]]))

        where_clauses = [
            "(" +
            " OR ".join(f"CONTAINS(LOWER(c[\"from\"]), @sender_{index})" for index, _ in enumerate(sender_variants)) +
            ")"
        ]
        params = [{"name": f"@sender_{index}", "value": candidate} for index, candidate in enumerate(sender_variants)]

        idx = 0
        for key, value in (security_filters or {}).items():
            idx += 1
            param_name = f"@p{idx}"
            where_clauses.append(f"c.securityMetadata.{key} = {param_name}")
            params.append({"name": param_name, "value": value})

        where_clause = " AND ".join(where_clauses)
        query = f"""
            SELECT VALUE COUNT(1)
            FROM c
            WHERE {where_clause}
        """

        try:
            results = list(
                self.container.query_items(
                    query=query,
                    parameters=params,
                    enable_cross_partition_query=True,
                )
            )
            if not results:
                return 0
            return int(results[0])
        except Exception as e:
            import logging

            logging.error(f"Cosmos DB sender count failed: {e}")
            logging.debug(f"Query: {query}")
            logging.debug(f"Parameters count: {len(params)}")
            raise
