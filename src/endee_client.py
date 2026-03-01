"""
Endee Vector Database Client
REST API wrapper for Endee running on Docker (localhost:8080)
API base: http://localhost:8080/api/v1/
"""
import requests
import json
from typing import List, Dict, Optional


ENDEE_BASE_URL = "http://localhost:8080/api/v1"
ENDEE_AUTH_TOKEN = ""  # Leave empty if running without auth


def _headers():
    h = {"Content-Type": "application/json"}
    if ENDEE_AUTH_TOKEN:
        h["Authorization"] = ENDEE_AUTH_TOKEN
    return h


class EndeeClient:
    """
    Client for Endee vector database.
    Handles index creation, vector insertion, and similarity search.
    """

    def __init__(self, base_url: str = ENDEE_BASE_URL, auth_token: str = ""):
        self.base_url = base_url
        self.auth_token = auth_token

    def _headers(self):
        h = {"Content-Type": "application/json"}
        if self.auth_token:
            h["Authorization"] = self.auth_token
        return h

    def health_check(self) -> bool:
        """Check if Endee server is running."""
        try:
            resp = requests.get(f"{self.base_url}/index/list",
                                headers=self._headers(), timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def list_indexes(self) -> List[str]:
        """List all existing indexes."""
        try:
            resp = requests.get(f"{self.base_url}/index/list",
                                headers=self._headers(), timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, list) else data.get("indexes", [])
        except Exception as e:
            print(f"[Endee] list_indexes error: {e}")
        return []

    def create_index(self, index_name: str, dimension: int,
                     metric: str = "cosine") -> bool:
        """
        Create a new vector index.
        dimension: size of embedding vectors (384 for all-MiniLM-L6-v2)
        metric: cosine | euclidean | dot_product
        """
        payload = {
            "name":      index_name,
            "dimension": dimension,
            "metric":    metric,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/index/create",
                headers=self._headers(),
                json=payload,
                timeout=10
            )
            if resp.status_code in (200, 201):
                print(f"[Endee] Index '{index_name}' created (dim={dimension}, metric={metric})")
                return True
            elif resp.status_code == 409:
                print(f"[Endee] Index '{index_name}' already exists — reusing")
                return True
            else:
                print(f"[Endee] create_index failed: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"[Endee] create_index error: {e}")
        return False

    def insert_vectors(self, index_name: str,
                       vectors: List[Dict]) -> bool:
        """
        Insert vectors into an index.
        Each vector dict: {"id": str, "vector": List[float], "metadata": dict}
        """
        payload = {"vectors": vectors}
        try:
            resp = requests.post(
                f"{self.base_url}/index/{index_name}/insert",
                headers=self._headers(),
                json=payload,
                timeout=30
            )
            if resp.status_code in (200, 201):
                print(f"[Endee] Inserted {len(vectors)} vectors into '{index_name}'")
                return True
            else:
                print(f"[Endee] insert_vectors failed: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"[Endee] insert_vectors error: {e}")
        return False

    def search(self, index_name: str, query_vector: List[float],
               top_k: int = 5, include_metadata: bool = True) -> List[Dict]:
        """
        Search for similar vectors.
        Returns list of {id, score, metadata} dicts sorted by similarity.
        """
        payload = {
            "vector":           query_vector,
            "top_k":            top_k,
            "include_metadata": include_metadata,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/index/{index_name}/search",
                headers=self._headers(),
                json=payload,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                # Endee returns results in "results" or direct list
                return data.get("results", data) if isinstance(data, dict) else data
            else:
                print(f"[Endee] search failed: {resp.status_code} {resp.text}")
        except Exception as e:
            print(f"[Endee] search error: {e}")
        return []

    def delete_index(self, index_name: str) -> bool:
        """Delete an index."""
        try:
            resp = requests.delete(
                f"{self.base_url}/index/{index_name}",
                headers=self._headers(),
                timeout=10
            )
            return resp.status_code in (200, 204)
        except Exception as e:
            print(f"[Endee] delete_index error: {e}")
        return False

    def index_stats(self, index_name: str) -> Dict:
        """Get stats for an index (vector count, dimension, etc.)"""
        try:
            resp = requests.get(
                f"{self.base_url}/index/{index_name}/stats",
                headers=self._headers(),
                timeout=5
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print(f"[Endee] index_stats error: {e}")
        return {}
