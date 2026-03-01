"""
SecureSearch Indexer
Converts the security knowledge base into vector embeddings
and stores them in Endee vector database.

Run this ONCE before using the search app:
    python src/indexer.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentence_transformers import SentenceTransformer
from src.endee_client import EndeeClient
from src.knowledge_base import get_all_entries

INDEX_NAME  = "securesearch"
EMBED_MODEL = "all-MiniLM-L6-v2"   # 384-dim, fast, good quality
DIMENSION   = 384
BATCH_SIZE  = 32


def build_text_for_embedding(entry: dict) -> str:
    """
    Combine title + description + example + tags into one rich text.
    Better embedding quality than indexing just the title.
    """
    parts = [
        entry["title"],
        entry["description"],
        entry.get("example", ""),
        " ".join(entry.get("tags", [])),
        entry.get("category_name", ""),
        entry.get("cwe", ""),
    ]
    return " | ".join(p for p in parts if p)


def run_indexer():
    print("=" * 55)
    print("  SecureSearch — Endee Indexer")
    print("=" * 55)

    # ── Step 1: Connect to Endee ───────────────────────────────
    client = EndeeClient()
    if not client.health_check():
        print("\n[ERROR] Cannot connect to Endee at http://localhost:8080")
        print("  Make sure Endee is running:")
        print("  docker run -p 8080:8080 endeeio/endee-server:latest")
        sys.exit(1)
    print("\n[OK] Connected to Endee")

    # ── Step 2: Load embedding model ──────────────────────────
    print(f"\n[*] Loading embedding model: {EMBED_MODEL}")
    model = SentenceTransformer(EMBED_MODEL)
    print(f"[OK] Model loaded (dimension={DIMENSION})")

    # ── Step 3: Create index ───────────────────────────────────
    client.create_index(INDEX_NAME, DIMENSION, metric="cosine")

    # ── Step 4: Embed and insert ───────────────────────────────
    entries = get_all_entries()
    print(f"\n[*] Embedding {len(entries)} knowledge base entries...")

    vectors_to_insert = []
    for i, entry in enumerate(entries):
        text = build_text_for_embedding(entry)
        embedding = model.encode(text, normalize_embeddings=True).tolist()

        vectors_to_insert.append({
            "id":     entry["id"],
            "vector": embedding,
            "metadata": {
                "id":            entry["id"],
                "title":         entry["title"],
                "category":      entry["category"],
                "category_name": entry["category_name"],
                "cwe":           entry.get("cwe", ""),
                "severity":      entry["severity"],
                "description":   entry["description"],
                "example":       entry.get("example", ""),
                "fix":           entry.get("fix", ""),
                "code_example":  entry.get("code_example", ""),
                "tags":          ", ".join(entry.get("tags", [])),
            }
        })

        if (i + 1) % 5 == 0:
            print(f"  Embedded {i+1}/{len(entries)} entries...")

    # Insert in batches
    print(f"\n[*] Inserting into Endee in batches of {BATCH_SIZE}...")
    for i in range(0, len(vectors_to_insert), BATCH_SIZE):
        batch = vectors_to_insert[i:i + BATCH_SIZE]
        client.insert_vectors(INDEX_NAME, batch)

    # ── Step 5: Verify ─────────────────────────────────────────
    stats = client.index_stats(INDEX_NAME)
    print(f"\n[OK] Indexing complete!")
    print(f"     Index: {INDEX_NAME}")
    print(f"     Vectors stored: {len(vectors_to_insert)}")
    if stats:
        print(f"     Endee stats: {stats}")
    print("\n  You can now run the search app:")
    print("  streamlit run app.py\n")


if __name__ == "__main__":
    run_indexer()
