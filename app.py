"""
SecureSearch — Semantic Vulnerability Search Engine
Powered by Endee Vector Database + Sentence Transformers

Run:
    streamlit run app.py
"""
import streamlit as st
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.search_engine import SecureSearchEngine

# ── Page config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureSearch",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ── Styling ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark background */
    .stApp { background-color: #060a0f; color: #d0dce8; }
    .stApp > header { background-color: transparent; }

    /* Sidebar */
    [data-testid="stSidebar"] { background-color: #0b1119; border-right: 1px solid #1a2535; }

    /* Search input */
    .stTextInput > div > div > input {
        background-color: #0f1822 !important;
        color: #d0dce8 !important;
        border: 1px solid #1a3a5a !important;
        border-radius: 8px !important;
        font-size: 16px !important;
        padding: 12px !important;
    }

    /* Cards */
    .result-card {
        background: #0f1822;
        border: 1px solid #1a2535;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 16px;
        border-left: 4px solid #00c8ff;
    }
    .result-card:hover { border-color: #00c8ff; }

    /* Severity badge */
    .badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: bold;
        margin-right: 6px;
    }

    /* Code blocks */
    .code-block {
        background: #0a0f18;
        border: 1px solid #1a2535;
        border-radius: 6px;
        padding: 12px;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        color: #00d68f;
        white-space: pre-wrap;
        overflow-x: auto;
    }

    /* Score bar */
    .score-bar-bg {
        background: #1a2535;
        border-radius: 4px;
        height: 6px;
        margin-top: 4px;
    }

    /* Metric cards */
    .metric-box {
        background: #0b1119;
        border: 1px solid #1a2535;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }

    /* Hide streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    .stDeployButton { display: none; }

    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0066cc, #00c8ff);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: bold;
        padding: 10px 24px;
        width: 100%;
    }

    /* Selectbox */
    .stSelectbox > div > div {
        background-color: #0f1822 !important;
        color: #d0dce8 !important;
        border-color: #1a3a5a !important;
    }

    h1, h2, h3 { color: #00c8ff !important; }
</style>
""", unsafe_allow_html=True)


# ── Initialize engine (cached) ─────────────────────────────────────────────
@st.cache_resource
def load_engine():
    return SecureSearchEngine()


# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 SecureSearch")
    st.markdown("*Semantic Vulnerability Search*")
    st.markdown("---")

    st.markdown("### Filters")
    severity_filter = st.selectbox(
        "Severity",
        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0
    )

    category_filter = st.selectbox(
        "OWASP Category",
        ["All", "A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
         "A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021"],
        index=0
    )

    top_k = st.slider("Number of results", 1, 10, 5)

    st.markdown("---")
    st.markdown("### Example Queries")
    example_queries = [
        "my login works with wrong password",
        "user can access other accounts by changing URL",
        "API key stored in source code",
        "SQL query built from user input",
        "eval used on form data",
        "no limit on login attempts",
        "password stored as MD5",
        "file upload with no type check",
        "server fetches URLs provided by user",
    ]
    for q in example_queries:
        if st.button(q, key=f"ex_{q[:20]}"):
            st.session_state["query_input"] = q

    st.markdown("---")
    st.markdown("**Powered by**")
    st.markdown("🗄️ [Endee Vector DB](https://github.com/endee-io/endee)")
    st.markdown("🤖 all-MiniLM-L6-v2")
    st.markdown("📚 OWASP Top 10 (2021)")


# ── Main content ───────────────────────────────────────────────────────────
st.markdown("""
<div style='padding: 20px 0 10px 0'>
    <h1 style='font-size: 2.5rem; margin: 0'>🔍 SecureSearch</h1>
    <p style='color: #7a9ab0; font-size: 1.1rem; margin: 4px 0 0 0'>
        Semantic vulnerability search powered by
        <span style='color: #00c8ff'>Endee Vector Database</span>
    </p>
</div>
""", unsafe_allow_html=True)

# ── Connection check ───────────────────────────────────────────────────────
engine = load_engine()
endee_ready = engine.is_ready()

if not endee_ready:
    st.error("""
    ⚠️ **Endee is not running or index not found.**

    Start Endee with Docker:
    ```bash
    docker run -p 8080:8080 endeeio/endee-server:latest
    ```
    Then index the knowledge base:
    ```bash
    python src/indexer.py
    ```
    """)
    st.stop()

# ── Stats row ──────────────────────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown("""<div class='metric-box'>
        <div style='font-size:1.8rem;color:#00c8ff;font-weight:bold'>25+</div>
        <div style='color:#7a9ab0;font-size:0.8rem'>Vulnerabilities Indexed</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown("""<div class='metric-box'>
        <div style='font-size:1.8rem;color:#00d68f;font-weight:bold'>10/10</div>
        <div style='color:#7a9ab0;font-size:0.8rem'>OWASP Top 10 Coverage</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown("""<div class='metric-box'>
        <div style='font-size:1.8rem;color:#fa8c16;font-weight:bold'>384</div>
        <div style='color:#7a9ab0;font-size:0.8rem'>Vector Dimensions</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown("""<div class='metric-box'>
        <div style='font-size:1.8rem;color:#e879f9;font-weight:bold'>Endee</div>
        <div style='color:#7a9ab0;font-size:0.8rem'>Vector Database</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Search box ─────────────────────────────────────────────────────────────
st.markdown("### Describe your security concern in plain English")

default_query = st.session_state.get("query_input", "")
query = st.text_input(
    label="search",
    value=default_query,
    placeholder="e.g. 'user can see other people's orders by changing the ID in the URL'",
    label_visibility="collapsed",
    key="main_search"
)

search_clicked = st.button("🔍 Search", use_container_width=False)

# ── Results ────────────────────────────────────────────────────────────────
if query and (search_clicked or query):
    with st.spinner("Searching Endee vector database..."):
        results = engine.search(
            query,
            top_k=top_k,
            severity_filter=severity_filter if severity_filter != "All" else None,
            category_filter=category_filter if category_filter != "All" else None,
        )

    if not results:
        st.warning("No results found. Try a different query or remove filters.")
    else:
        st.markdown(f"**{len(results)} results** for: *\"{query}\"*")
        st.markdown("---")

        for i, r in enumerate(results):
            sev   = r["severity"]
            cat   = r["category"]
            score = r["similarity_pct"]

            # Severity badge color
            sev_colors = {
                "CRITICAL": ("#ff4d4f", "#2d1a1a"),
                "HIGH":     ("#fa8c16", "#2d1e0a"),
                "MEDIUM":   ("#fadb14", "#2d2a0a"),
                "LOW":      ("#52c41a", "#0f2d0a"),
            }
            sev_fg, sev_bg = sev_colors.get(sev, ("#888", "#111"))
            owasp_color = r["owasp_color"]

            with st.expander(
                f"{'🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '🟢'} "
                f"**{r['title']}** — {score}% match",
                expanded=(i == 0)
            ):
                # Header row
                hcol1, hcol2, hcol3 = st.columns([2, 2, 1])
                with hcol1:
                    st.markdown(
                        f"<span class='badge' style='background:{sev_bg};color:{sev_fg};border:1px solid {sev_fg}'>"
                        f"{sev}</span>"
                        f"<span class='badge' style='background:#0b1a2a;color:{owasp_color};border:1px solid {owasp_color}'>"
                        f"{cat}</span>",
                        unsafe_allow_html=True
                    )
                with hcol2:
                    st.markdown(
                        f"<span style='color:#7a9ab0;font-size:0.85rem'>"
                        f"📋 {r['category_name']} &nbsp;|&nbsp; 🔗 {r['cwe']}</span>",
                        unsafe_allow_html=True
                    )
                with hcol3:
                    st.markdown(
                        f"<div style='text-align:right;color:#00c8ff;font-weight:bold'>"
                        f"Similarity: {score}%</div>",
                        unsafe_allow_html=True
                    )

                # Score bar
                st.markdown(
                    f"<div class='score-bar-bg'>"
                    f"<div style='width:{score}%;background:linear-gradient(90deg,#0066cc,#00c8ff);"
                    f"height:6px;border-radius:4px'></div></div>",
                    unsafe_allow_html=True
                )

                st.markdown("<br>", unsafe_allow_html=True)

                # Description
                st.markdown("**What is this vulnerability?**")
                st.markdown(
                    f"<div style='color:#c0d0e0;line-height:1.6'>{r['description']}</div>",
                    unsafe_allow_html=True
                )

                # Example
                if r.get("example"):
                    st.markdown("<br>**Real-world example:**")
                    st.markdown(
                        f"<div style='color:#fa8c16;background:#1a1500;padding:10px;"
                        f"border-radius:6px;border-left:3px solid #fa8c16'>"
                        f"⚠️ {r['example']}</div>",
                        unsafe_allow_html=True
                    )

                # Fix
                if r.get("fix"):
                    st.markdown("<br>**How to fix it:**")
                    st.markdown(
                        f"<div style='color:#00d68f;background:#001a0a;padding:10px;"
                        f"border-radius:6px;border-left:3px solid #00d68f'>"
                        f"✅ {r['fix']}</div>",
                        unsafe_allow_html=True
                    )

                # Code example
                if r.get("code_example"):
                    st.markdown("<br>**Code example:**")
                    st.code(r["code_example"], language="python")

                # Tags
                if r.get("tags"):
                    tags = [t.strip() for t in r["tags"].split(",")]
                    tag_html = " ".join(
                        f"<span style='background:#0f2035;color:#7abaff;"
                        f"padding:2px 8px;border-radius:10px;font-size:11px;"
                        f"margin:2px;display:inline-block'>#{t}</span>"
                        for t in tags if t
                    )
                    st.markdown(f"<div style='margin-top:8px'>{tag_html}</div>",
                                unsafe_allow_html=True)

# ── Empty state ────────────────────────────────────────────────────────────
if not query:
    st.markdown("""
    <div style='text-align:center;padding:60px 20px;color:#3a5a7a'>
        <div style='font-size:3rem'>🔍</div>
        <div style='font-size:1.2rem;margin-top:12px'>
            Describe a security problem in plain English
        </div>
        <div style='font-size:0.9rem;margin-top:8px'>
            SecureSearch uses <b style='color:#00c8ff'>Endee</b> vector similarity search
            to find the most relevant vulnerability — even if you don't know the technical name
        </div>
        <br>
        <div style='color:#2a4a6a;font-size:0.85rem'>
            Try: "user input goes directly into SQL query" or
            "login succeeds with any password"
        </div>
    </div>
    """, unsafe_allow_html=True)
