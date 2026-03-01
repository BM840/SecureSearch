# 🔍 SecureSearch

**Semantic Vulnerability Search Engine powered by Endee Vector Database**

> Describe a security problem in plain English — SecureSearch finds the exact vulnerability, its OWASP category, real-world examples, and working code fixes. No technical jargon required.

---

## 🎯 Problem Statement

Security knowledge is scattered across OWASP docs, CWE databases, CVE listings, and Stack Overflow. When a developer encounters a potential vulnerability, they face two problems:

1. **They don't know what it's called** — they can describe it in plain English but can't search for it technically
2. **Keyword search fails** — searching "login bug" returns nothing useful, even if the database contains the exact matching vulnerability documented as "Authentication Bypass via Always-True Condition (CWE-287)"

**Traditional keyword search fails here.** Vector semantic search doesn't.

---

## 💡 Solution

SecureSearch converts the entire OWASP Top 10 (2021) knowledge base — including all 10 categories, 25+ vulnerability entries with real-world examples and code fixes — into **vector embeddings stored in Endee**.

When you search, your plain English query is embedded into the same vector space and Endee finds the semantically closest vulnerabilities by **cosine similarity** — not keyword matching.

```
User: "my login always works even with the wrong password"
                        ↓
          Embed query → 384-dimensional vector
                        ↓
          Endee cosine similarity search
                        ↓
Result: "Authentication Bypass — Always-True Condition"
        CWE-287 | A07:2021 | CRITICAL | 94.2% match
        Fix: Remove 'or True', use bcrypt.checkpw()
```

---

## 🏗️ System Design

```
┌─────────────────────────────────────────────────────────────┐
│                      SecureSearch                            │
│                                                              │
│  ┌──────────────┐    ┌───────────────────────────────────┐  │
│  │ Knowledge    │    │         Indexer (run once)        │  │
│  │ Base         │───▶│  sentence-transformers            │  │
│  │              │    │  all-MiniLM-L6-v2 (384 dim)      │  │
│  │ • OWASP A01  │    │  → 384-dimensional embeddings     │  │
│  │ • OWASP A02  │    └──────────────┬────────────────────┘  │
│  │ • ...        │                   │ INSERT vectors         │
│  │ • OWASP A10  │                   ▼                        │
│  │ • 25+ entries│    ┌──────────────────────────────────┐   │
│  └──────────────┘    │   ENDEE VECTOR DATABASE          │   │
│                      │   localhost:8080 (Docker)        │   │
│  ┌──────────────┐    │   Index: securesearch            │   │
│  │ User Query   │    │   Metric: cosine similarity      │   │
│  │              │    │   Dimension: 384                 │   │
│  │ plain English│───▶│                                  │   │
│  │ description  │    │   SEARCH → top-k similar vectors │   │
│  └──────────────┘    └──────────────┬────────────────────┘  │
│                                     │ results + metadata     │
│                                     ▼                        │
│                      ┌──────────────────────────────────┐   │
│                      │   Streamlit Dashboard            │   │
│                      │   • Similarity score             │   │
│                      │   • OWASP category               │   │
│                      │   • CWE ID                       │   │
│                      │   • Real-world example           │   │
│                      │   • Working code fix             │   │
│                      └──────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Why Endee?

| Feature | Endee | Traditional DB |
|---|---|---|
| Semantic similarity search | ✅ Native | ❌ Not possible |
| Sub-millisecond query latency | ✅ Optimized | ❌ Slow for vectors |
| Scales to 1B vectors single node | ✅ Yes | ❌ No |
| Simple REST API | ✅ HTTP/JSON | — |
| Self-hosted / offline | ✅ Docker | — |
| Metadata filtering | ✅ Yes | — |

---

## 🛠️ How Endee Is Used

### 1. Index Creation
```python
client.create_index("securesearch", dimension=384, metric="cosine")
```

### 2. Vector Insertion
Each vulnerability entry is converted to a rich text combining title + description + example + tags, then embedded and stored:
```python
embedding = model.encode(text, normalize_embeddings=True).tolist()
client.insert_vectors("securesearch", [{
    "id":     "A03-001",
    "vector": embedding,        # 384 floats
    "metadata": {               # Full vulnerability data stored alongside
        "title":       "SQL Injection via String Concatenation",
        "category":    "A03:2021",
        "severity":    "CRITICAL",
        "cwe":         "CWE-89",
        "description": "...",
        "fix":         "...",
        "code_example":"...",
    }
}])
```

### 3. Semantic Search
```python
query_vector = model.encode(user_query, normalize_embeddings=True).tolist()
results = client.search("securesearch", query_vector, top_k=5)
# Returns: [{id, score, metadata}, ...] sorted by cosine similarity
```

The key insight: **"my login works with any password"** and **"authentication bypass always-true condition"** are semantically similar in vector space even though they share no keywords.

---

## 📁 Project Structure

```
securesearch/
├── app.py                    # Streamlit dashboard
├── requirements.txt
├── README.md
└── src/
    ├── endee_client.py       # Endee REST API wrapper
    ├── indexer.py            # Embeds and indexes knowledge base
    ├── search_engine.py      # Search logic + result formatting
    └── knowledge_base.py     # OWASP Top 10 vulnerability dataset
```

---

## ⚡ Setup & Run

### Prerequisites
- Python 3.10+
- Docker Desktop
- 2GB disk space (for sentence-transformers model)

### Step 1 — Star & Fork Endee
```
1. Star: https://github.com/endee-io/endee
2. Fork to your GitHub account
```

### Step 2 — Start Endee
```bash
docker run -p 8080:8080 endeeio/endee-server:latest
```
Verify it's running: `curl http://localhost:8080/api/v1/index/list`

### Step 3 — Install dependencies
```bash
git clone https://github.com/YOUR_USERNAME/securesearch
cd securesearch
pip install -r requirements.txt
```

### Step 4 — Index the knowledge base (run once)
```bash
python src/indexer.py
```
Output:
```
[OK] Connected to Endee
[OK] Model loaded (dimension=384)
[Endee] Index 'securesearch' created
[Endee] Inserted 25 vectors into 'securesearch'
[OK] Indexing complete!
```

### Step 5 — Launch the app
```bash
streamlit run app.py
```
Open: http://localhost:8501

---

## 🔍 Example Searches

| Your Query | What SecureSearch Finds |
|---|---|
| "login works with any password" | Authentication Bypass — CWE-287, A07:2021 |
| "user changes URL number to see other accounts" | IDOR — CWE-639, A01:2021 |
| "API key in source code on GitHub" | Hardcoded Secret — CWE-798, A02:2021 |
| "SQL query built from form input" | SQL Injection — CWE-89, A03:2021 |
| "eval() on user data" | Code Injection via eval() — CWE-95, A03:2021 |
| "no limit on password attempts" | No Rate Limiting — CWE-307, A04:2021 |
| "password stored as MD5" | Weak Password Hashing — CWE-328, A02:2021 |
| "server fetches URL from user" | SSRF — CWE-918, A10:2021 |

---

## 🧠 Why Semantic Search Is Better

**Keyword search (fails):**
```
Query: "my login always lets people in"
DB has: "Authentication Bypass via Always-True Condition"
Result: 0 matches ← no shared keywords
```

**Vector semantic search (works):**
```
Query vector:  [0.23, 0.87, 0.12, ...]  ← "login lets people in"
DB vector:     [0.25, 0.84, 0.15, ...]  ← "Authentication Bypass"
Cosine similarity: 0.94 ← 94% match ✅
```

The embeddings capture **meaning**, not words.

---

## 📊 Coverage

- ✅ OWASP Top 10 (2021) — all 10 categories
- ✅ 25+ vulnerability entries
- ✅ Every entry includes: description, real example, fix, code sample, CWE ID
- ✅ Severity levels: CRITICAL / HIGH / MEDIUM / LOW
- ✅ Filter by severity and OWASP category

---

## 🔗 Links

- **Endee Vector Database:** https://github.com/endee-io/endee
- **OWASP Top 10 (2021):** https://owasp.org/Top10/
- **Embedding Model:** https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2

---

## 👤 Author

**Bharat Maheshwari**
Bennett University — CSE
GitHub: github.com/BM840
