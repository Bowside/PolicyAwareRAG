from azure.identity import DefaultAzureCredential
from azure.cosmos import CosmosClient
from typing import List, Dict, Any
import numpy as np

class ConflictAwareRetriever:
    def __init__(self, cosmos_endpoint: str, database_name: str, container_name: str):
        """Create a retriever backed by a Cosmos DB container.

        Args:
            cosmos_endpoint: Cosmos DB account endpoint URI.
            database_name: Database name containing the vector container.
            container_name: Container name used for retrieval.
        """
        credential = DefaultAzureCredential()
        self.client = CosmosClient(url=cosmos_endpoint, credential=credential)
        self.db = self.client.get_database_client(database_name)
        self.container = self.db.get_container_client(container_name)

    def _cosine_sim(self, a: np.ndarray, b: np.ndarray) -> float:
        """Compute cosine similarity between two vectors.

        Args:
            a: First embedding vector.
            b: Second embedding vector.

        Returns:
            A similarity score in the range ``[-1.0, 1.0]`` or ``0.0`` for zero vectors.
        """
        if np.linalg.norm(a) == 0 or np.linalg.norm(b) == 0:
            return 0.0
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def retrieve(self, query_embedding: List[float], security_filters: Dict[str, Any], top_k: int = 10) -> List[Dict]:
        """Retrieve the highest-scoring chunks that satisfy the security filters.

        Args:
            query_embedding: Query embedding vector used for similarity ranking.
            security_filters: Metadata filters applied to the Cosmos query.
            top_k: Maximum number of ranked items to return.

        Returns:
            A list of matching chunk dictionaries ordered by descending similarity.
        """
        where_clauses = []
        params = []
        idx = 0
        for k, v in security_filters.items():
            idx += 1
            param_name = f"@p{idx}"
            where_clauses.append(f"c.securityMetadata.{k} = {param_name}")
            params.append({"name": param_name, "value": v})
        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"
        query = f"SELECT TOP 100 c.id, c.content, c.embedding, c.securityMetadata FROM c WHERE {where_sql}"
        items = list(self.container.query_items(query=query, parameters=params, enable_cross_partition_query=True))
        q_emb = np.array(query_embedding, dtype=float)
        scored = []
        for it in items:
            emb = np.array(it.get("embedding", []), dtype=float)
            score = self._cosine_sim(q_emb, emb) if emb.size else 0.0
            scored.append((score, it))
        scored.sort(key=lambda x: x[0], reverse=True)
        top_items = [i for s, i in scored[:top_k]]
        return top_items
