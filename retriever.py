import logging
import os
import re
from typing import Any, Dict, List, Optional

from azure.cosmos import CosmosClient

class ConflictAwareRetriever:
    def __init__(self, container_name: Optional[str] = None):
        """Create a retriever backed by a Cosmos DB container.

        Args:
            cosmos_endpoint: Cosmos DB account endpoint URI. Falls back to the COSMOSDB_ENDPOINT environment variable.
            database_name: Database name containing the vector container. Falls back to the COSMOSDB_DATABASE environment variable.
            container_name: Container name used for retrieval. Falls back to EnronEmailVectorStore.
            cosmos_key: Cosmos DB account key. Falls back to the COSMOS_KEY environment variable.
        """
        cosmos_endpoint = os.environ.get("COSMOSDB_ENDPOINT")
        database_name = os.environ.get("COSMOSDB_DATABASE")
        container_name = container_name or os.environ.get("COSMOSDB_ENRON_COLLECTION")
        credential = os.environ.get("COSMOSDB_KEY")
        if not cosmos_endpoint:
            raise ValueError("COSMOSDB_ENDPOINT must be provided to initialize the Cosmos client.")
        if not database_name:
            raise ValueError("COSMOSDB_DATABASE must be provided to initialize the Cosmos client.")
        if not credential:
            raise ValueError("COSMOS_KEY must be provided to initialize the Cosmos client.")

        self.client = CosmosClient(url=cosmos_endpoint, credential=credential)
        self.db = self.client.get_database_client(database_name)
        self.container = self.db.get_container_client(container_name)

    @staticmethod
    def _policy_role_allows(item: Dict[str, Any], active_policy_role: Any) -> bool:
        """Return True when a result should be kept for the active policy role.

        Records without ``securityMetadata`` are always returned. Records with a
        ``securityMetadata.policyRole`` list must match the active role exactly.
        """
        metadata = item.get("securityMetadata") or {}
        policy_roles = metadata.get("policyRole")

        if policy_roles in (None, "", [], {}):
            return True

        if not active_policy_role:
            return False

        if isinstance(policy_roles, str):
            candidates = [policy_roles]
        elif isinstance(policy_roles, list):
            candidates = policy_roles
        else:
            candidates = [str(policy_roles)]

        normalized_active = str(active_policy_role).strip().lower()
        normalized_candidates = {str(candidate).strip().lower() for candidate in candidates if str(candidate).strip()}
        return normalized_active in normalized_candidates

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
            active_policy_role = security_filters.get("policyRole") or security_filters.get("role")
            filtered_items = [
                item for item in items
                if self._policy_role_allows(item, active_policy_role)
            ]
            logging.info("Cosmos vector query returned %s item(s)", len(filtered_items))
            return filtered_items
        except Exception as e:
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
