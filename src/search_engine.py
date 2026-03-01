"""
SecureSearch — Search Engine
Converts a plain English query into a vector embedding,
searches Endee, and returns ranked security knowledge results.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentence_transformers import SentenceTransformer
from src.endee_client import EndeeClient
from typing import List, Dict

INDEX_NAME  = "securesearch"
EMBED_MODEL = "all-MiniLM-L6-v2"

# Severity color mapping
SEVERITY_COLOR = {
    "CRITICAL": "#ff4d4f",
    "HIGH":     "#fa8c16",
    "MEDIUM":   "#fadb14",
    "LOW":      "#52c41a",
}

# OWASP category colors
OWASP_COLOR = {
    "A01:2021": "#fb923c",
    "A02:2021": "#f59e0b",
    "A03:2021": "#a3e635",
    "A04:2021": "#34d399",
    "A05:2021": "#22d3ee",
    "A06:2021": "#818cf8",
    "A07:2021": "#e879f9",
    "A08:2021": "#f472b6",
    "A09:2021": "#94a3b8",
    "A10:2021": "#67e8f9",
}


class SecureSearchEngine:
    """
    Semantic security vulnerability search engine powered by Endee.
    Searches by meaning — not just keywords.
    """

    def __init__(self):
        self.client = EndeeClient()
        self._model = None  # Lazy load

    @property
    def model(self):
        if self._model is None:
            self._model = SentenceTransformer(EMBED_MODEL)
        return self._model

    def is_ready(self) -> bool:
        """Check if Endee is running and index exists."""
        if not self.client.health_check():
            return False
        indexes = self.client.list_indexes()
        return INDEX_NAME in str(indexes)

    def search(self, query: str, top_k: int = 5,
               severity_filter: str = None,
               category_filter: str = None) -> List[Dict]:
        """
        Search for security vulnerabilities matching the query.

        Args:
            query: Plain English description of the issue
            top_k: Number of results to return
            severity_filter: Filter by CRITICAL/HIGH/MEDIUM/LOW
            category_filter: Filter by OWASP category e.g. "A03:2021"

        Returns:
            List of result dicts with metadata + similarity score
        """
        if not query.strip():
            return []

        # Embed the query
        query_vector = self.model.encode(
            query,
            normalize_embeddings=True
        ).tolist()

        # Search Endee — get more results if filtering
        fetch_k = top_k * 3 if (severity_filter or category_filter) else top_k
        raw_results = self.client.search(INDEX_NAME, query_vector, top_k=fetch_k)

        if not raw_results:
            return []

        # Parse and enrich results
        results = []
        for r in raw_results:
            meta = r.get("metadata", {})
            if not meta:
                continue

            score = r.get("score", 0)

            # Apply filters
            if severity_filter and severity_filter != "All":
                if meta.get("severity", "").upper() != severity_filter.upper():
                    continue
            if category_filter and category_filter != "All":
                if not meta.get("category", "").startswith(category_filter):
                    continue

            results.append({
                "id":            meta.get("id", ""),
                "title":         meta.get("title", ""),
                "category":      meta.get("category", ""),
                "category_name": meta.get("category_name", ""),
                "cwe":           meta.get("cwe", ""),
                "severity":      meta.get("severity", ""),
                "description":   meta.get("description", ""),
                "example":       meta.get("example", ""),
                "fix":           meta.get("fix", ""),
                "code_example":  meta.get("code_example", ""),
                "tags":          meta.get("tags", ""),
                "score":         round(float(score), 4),
                "similarity_pct": round(float(score) * 100, 1),
                "severity_color": SEVERITY_COLOR.get(meta.get("severity", ""), "#888"),
                "owasp_color":    OWASP_COLOR.get(meta.get("category", ""), "#888"),
            })

        return results[:top_k]

    def get_stats(self) -> Dict:
        """Get index statistics from Endee."""
        return self.client.index_stats(INDEX_NAME)
