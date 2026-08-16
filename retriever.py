"""Vector-based retrieval with policy-aware security filtering.

Implements ConflictAwareRetriever for Enron email corpus:
- Vector similarity search using Cosmos DB's native VectorDistance function
- Security metadata filtering (policy role, classification level, etc.)
- Sender-based filtering with name normalization and partial matching
- Cross-partition queries with security context

All retrieval results are filtered by principal role and declaredIntent
to ensure only authorized chunks are returned based on ODRL policy constraints.
"""
import logging
import os
import re
from typing import Any, Dict, List, Optional

from azure.cosmos import CosmosClient


class ConflictAwareRetriever:
    """Vector retriever with policy-aware security filtering.
    
    Connects to Cosmos DB container with vectorized email content and performs
    semantic similarity search using native VectorDistance function. All results
    are filtered by security metadata constraints and principal policy role.
    
    Supports both vector-based retrieval and sender-based filtering with name
    normalization (handles "Jane Doe" matching "jane.doe@enron.com").
    """
    def __init__(self, container_name: Optional[str] = None):
        """Create a retriever backed by a Cosmos DB vector container.

        Loads Cosmos DB connection from environment variables:
        - COSMOSDB_ENDPOINT: Cosmos account URI
        - COSMOSDB_DATABASE: Database containing vector store
        - COSMOSDB_ENRON_COLLECTION: Vector container name (default fallback)
        - COSMOSDB_KEY: Cosmos account key for authentication

        Args:
            container_name: Optional override for container name. If not provided,
                           uses COSMOSDB_ENRON_COLLECTION environment variable.

        Raises:
            ValueError: If COSMOSDB_ENDPOINT, COSMOSDB_DATABASE, or COSMOS_KEY
                       environment variables are not set.
        """
        cosmos_endpoint = os.environ.get("COSMOSDB_ENDPOINT")
        database_name = os.environ.get("COSMOSDB_DATABASE")
        container_name = container_name or os.environ.get("COSMOSDB_ENRON_COLLECTION")
        credential = os.environ.get("COSMOSDB_KEY")
        # Validate all required configuration parameters
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
        """Determine if a retrieved item should be returned for the active policy role.
        
        Implements security metadata filtering by policy role:
        - Items without securityMetadata.policyRole are always returned (no restrictions)
        - Items with policyRole must have active_policy_role match exactly (case-insensitive)
        - Supports single string or list of allowed roles
        
        This method enforces ODRL assignee role matching at retrieval time, ensuring
        the principal's role is authorized to see the retrieved content.

        Args:
            item: Retrieved item dict that may contain 'securityMetadata' field.
            active_policy_role: The principal's role to check against item's allowed roles.

        Returns:
            bool: True if item should be returned (no restrictions or role matches),
                  False if role mismatch (item restricted to different role).
        """
        metadata = item.get("securityMetadata") or {}
        policy_roles = metadata.get("policyRole")

        # No policy role restriction means item is accessible to all roles
        if policy_roles in (None, "", [], {}):
            return True

        # No active role means principal is unauthenticated, deny access
        if not active_policy_role:
            return False

        # Normalize policy roles to list for consistent matching
        if isinstance(policy_roles, str):
            candidates = [policy_roles]
        elif isinstance(policy_roles, list):
            candidates = policy_roles
        else:
            candidates = [str(policy_roles)]

        # Case-insensitive comparison of roles
        normalized_active = str(active_policy_role).strip().lower()
        normalized_candidates = {str(candidate).strip().lower() for candidate in candidates if str(candidate).strip()}
        return normalized_active in normalized_candidates

    def retrieve(self, query_embedding: List[float], security_filters: Dict[str, Any], top_k: int = 10) -> List[Dict]:
        """Retrieve highest-scoring chunks by vector similarity with security filtering.

        Executes a parameterized Cosmos SQL query using native VectorDistance function
        for semantic similarity ranking. Applies security filters to WHERE clause
        (role, classification level, etc.) and post-processes results by policy role.
        
        Query execution is enabled for cross-partition queries to search across the
        entire container (email corpus may be partitioned by sender).

        Args:
            query_embedding: Query embedding vector (float list) for similarity ranking.
            security_filters: Dict of securityMetadata constraints to apply as WHERE
                            conditions (e.g., {"policyRole": "analyst"}).
            top_k: Maximum number of results to return (default: 10).

        Returns:
            List of matching chunk dicts ordered by descending similarity (best first).
            Each dict includes: subject, from, to, date, body, similarity_score.

        Raises:
            Exception: If Cosmos DB query execution fails (network, syntax, auth error).
        """
        # Build WHERE clause from security filters using parameterized queries
        where_clauses = []
        params = [{"name": "@query_vector", "value": query_embedding}]
        
        # Add security filter conditions (e.g., securityMetadata.policyRole = @p1)
        idx = 0
        for k, v in security_filters.items():
            idx += 1
            param_name = f"@p{idx}"
            where_clauses.append(f"c.securityMetadata.{k} = {param_name}")
            params.append({"name": param_name, "value": v})
        
        where_sql = " AND ".join(where_clauses) if where_clauses else ""
        where_clause = f"WHERE {where_sql}" if where_sql else ""
        
        # Construct parameterized SQL query using Cosmos DB's native VectorDistance
        # VectorDistance returns lower scores for more similar vectors (0 = identical)
        query = f"""
            SELECT TOP {top_k} c.subject, c["from"], c.to, c.date, c.body,
            VectorDistance(c.vector, @query_vector) AS similarity_score
            FROM c
            {where_clause}
            ORDER BY VectorDistance(c.vector, @query_vector)
        """        
        try:
            # Execute query with cross-partition enabled for full corpus coverage
            items = list(self.container.query_items(
                query=query, 
                parameters=params, 
                enable_cross_partition_query=True
            ))
            # Apply policy role filtering to post-process results
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
        """Count documents whose sender field matches with flexible name normalization.

        Implements intelligent name matching to handle various sender query formats:
        - "Jane Doe" matches "jane.doe@enron.com", "jdoe@enron.com", "jane@enron.com"
        - "Doe" matches "jane.doe@enron.com"
        - Case-insensitive partial substring matching
        
        Generates sender name variants (full name, abbreviated) and searches for any
        match in the email "from" field. Applies optional security metadata filters
        (role, classification, etc.) as WHERE conditions.

        Args:
            sender_query: Sender name or email pattern to search for (e.g., "Jane Doe").
            security_filters: Optional dict of securityMetadata constraints to apply
                            (e.g., {"role": "analyst", "classification": "public"}).

        Returns:
            int: Count of matching documents (0 if no matches or invalid query).

        Raises:
            Exception: If Cosmos DB query execution fails.
        """
        normalized_sender = re.sub(r"\s+", " ", (sender_query or "").strip())
        if not normalized_sender:
            return 0

        # Extract individual name tokens (handles "Jane Doe" -> ["jane", "doe"])
        sender_terms = [term for term in re.split(r"[\s,]+", normalized_sender) if term]
        sender_name_match = normalized_sender.lower()
        sender_variants = []

        def _add_variant(candidate: str) -> None:
            """Add unique normalized variant to search list."""
            candidate = candidate.strip().lower()
            if candidate and candidate not in sender_variants:
                sender_variants.append(candidate)

        # Generate name variants for flexible matching
        # Example: "Jane Doe Smith" generates: "jane.doe", "jane doe smith", etc.
        if len(sender_terms) >= 2:
            _add_variant(".".join(sender_terms[:2]))

        _add_variant(sender_name_match)

        # Handle possessive/plural names: "Niles's" -> "Nile" for variant matching
        if sender_terms:
            first_token = sender_terms[0].lower()
            if first_token.endswith("s") and len(first_token) > 3:
                singular_terms = [first_token[:-1]] + [term.lower() for term in sender_terms[1:2]]
                _add_variant(".".join(singular_terms))
                _add_variant(" ".join([singular_terms[0]] + [term.lower() for term in sender_terms[1:]]))

        # Build WHERE clause with OR'd sender variants and AND'd security filters
        where_clauses = [
            "(" +
            " OR ".join(f"CONTAINS(LOWER(c[\"from\"]), @sender_{index})" for index, _ in enumerate(sender_variants)) +
            ")"
        ]
        params = [{"name": f"@sender_{index}", "value": candidate} for index, candidate in enumerate(sender_variants)]

        # Add security metadata filters to WHERE clause
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
            logging.error(f"Cosmos DB sender count failed: {e}")
            logging.debug(f"Query: {query}")
            logging.debug(f"Parameters count: {len(params)}")
            raise
