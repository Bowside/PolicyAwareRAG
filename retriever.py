import os
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
            SELECT TOP {top_k} c.id, c.content, c.embedding, c.securityMetadata,
            VectorDistance(c.embedding, @query_vector) AS similarity_score
            FROM c
            {where_clause}
            ORDER BY VectorDistance(c.embedding, @query_vector)
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
