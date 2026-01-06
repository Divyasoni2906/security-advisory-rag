# Vulnerability Intelligence System (RAG-Based)

A curated **security knowledge system** that combines **authoritative vulnerability advisories** with **educational explanations**, designed to prioritize correctness over noise.

This project focuses on *depth over volume* by indexing a small set of real vulnerabilities from real projects and explaining them using trusted sources.

---

## Why This Project?

Most vulnerability chatbots or CVE tools fail in two ways:

1. They index **too much unverified content**
2. They **don’t distinguish** between authoritative data and explanations

This system fixes that by:
- Treating **GitHub Security Advisories (GHSA)** as the source of truth
- Using educational content **only to explain concepts**, not replace facts

The goal is to answer:
- *What is the vulnerability?*
- *Why does it occur?*
- *How should developers reason about it?*

---

## Design Philosophy

### Curated Depth Over Scale
Instead of indexing thousands of CVEs, this system focuses on a **small, carefully selected set of real vulnerabilities** originating from my own applications.

This enables:
- Higher confidence answers
- Better reasoning
- Clear explainability

### Authority-First Retrieval
All queries prioritize **official advisories** first.  
Educational sources are used only to provide **context and understanding**.

---

## Architecture Overview
User Query
↓
React Frontend
↓
FastAPI Backend
↓
Metadata-Aware Retrieval
├── GitHub Security Advisories (Primary)
└── Educational Transcripts (Secondary)
↓
Chroma Vector Database
↓
LLM Response + Source Attribution


---

## Data Sources

### Authoritative
- GitHub Security Advisories (GHSA)
- Vulnerabilities identified in real projects

### Educational
- Curated YouTube tutorials explaining vulnerability classes:
  - SSRF
  - Path Traversal
  - Command Injection
  - ReDoS
  - Prototype Pollution
  - Client-side trust boundary issues

> Educational content is **never treated as ground truth**.

---

## Retrieval Strategy

The system uses a **two-phase retrieval approach**:

1. **Primary retrieval**
   - Filters for authoritative advisory documents
2. **Secondary retrieval**
   - Fetches educational explanations for context

Results are ranked using **metadata-aware scoring**, not keyword repetition.

---

## Chunking Strategy

- **GitHub Advisories**
  - Semantic, word-based chunks
- **YouTube Transcripts**
  - Time-based chunks (~60 seconds)

This hybrid approach improves retrieval quality across very different content types.

---

## Challenges & Learnings

- Verbose sources dominating similarity search  
  → Solved using source-aware retrieval

- Transcript ingestion rate limits  
  → Implemented caching and one-time ingestion

- Small dataset bias  
  → Addressed through careful curation and prioritization


---

## Tech Stack

- **Frontend**: React
- **Backend**: FastAPI
- **Vector Database**: ChromaDB
- **Embeddings**: HuggingFace (`all-MiniLM-L6-v2`)
- **RAG Framework**: LangChain
- **APIs**: GitHub GraphQL, YouTube Transcript API

---

## Future Enhancements

- Expand curated vulnerability set
- Map vulnerabilities to OWASP Top 10
- Improve semantic re-ranking
- Add answer quality evaluation

---

## Security Note

Environment variables and generated data are excluded from version control.  
See `.gitignore` for details.


