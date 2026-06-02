# Vulnerability Intelligence System (RAG-Based)

A security-focused Retrieval-Augmented Generation (RAG) system that combines authoritative vulnerability advisories with educational explanations, designed to prioritize correctness, source grounding, and explainability over raw data volume.

The system answers questions about real-world vulnerabilities while clearly distinguishing between factual security advisory data and educational content.

---

## 🎥 Demo

See the uploaded demo video.

---
## Snapshots
<img width="1366" height="616" alt="Screenshot (289)" src="https://github.com/user-attachments/assets/c2dea00e-99a9-421e-9a50-7220435efe24" />
When a query does not match any known GitHub Security Advisories, the application gracefully informs the user that no relevant results were found.
<img width="1366" height="635" alt="Screenshot (291)" src="https://github.com/user-attachments/assets/0a7f0d8b-1d1d-496b-8174-5264f33f7222" />

### Known Vulnerability Query

The system retrieves official GitHub Security Advisories first, supplements them with educational context when necessary, and generates structured responses covering:

* Technical definition
* Security impact
* Remediation guidance
* Additional learning

### Unknown Vulnerability Query

When a query does not match any indexed GitHub Security Advisories, the system gracefully informs the user that no relevant advisory information is available rather than fabricating an answer.

---

# Why This Project?

Many vulnerability chatbots fail in two ways:

* They index large amounts of unverified content.
* They do not distinguish between authoritative information and explanations.

This project addresses both issues by:

* Treating GitHub Security Advisories (GHSA) as the primary source of truth.
* Using educational content only to explain concepts and attack techniques.
* Maintaining source awareness throughout retrieval and generation.

The goal is to help developers answer:

* What is the vulnerability?
* Why does it occur?
* What impact can it have?
* How should it be mitigated?
* How can developers reason about similar security issues?

---

# Design Philosophy

## Curated Depth Over Scale

Instead of indexing thousands of vulnerabilities, the system focuses on a carefully selected set of real vulnerabilities affecting widely used software packages.

This enables:

* Higher confidence answers
* Better explainability
* More reliable retrieval
* Easier validation of outputs

---

## Authority-First Retrieval

The retrieval pipeline prioritizes authoritative GitHub advisories whenever relevant.

Educational sources are used only for:

* Conceptual understanding
* Attack explanations
* Security learning

They are never treated as the primary factual source.

---

# Architecture Overview

```text
User Query
    ↓
React Frontend
    ↓
FastAPI Backend
    ↓
Hybrid Retrieval Pipeline
    ├── GitHub Security Advisories (Primary)
    └── Educational Tutorials (Secondary)
    ↓
Chroma Vector Database
    ↓
Gemini 2.5 Flash
    ↓
Structured Response + Source Attribution
```

---

# Observability & Validation

The system integrates LangSmith to trace and analyze end-to-end RAG behavior.

LangSmith was used to:

* Inspect retrieval quality
* Analyze source attribution
* Debug ranking issues
* Validate grounding behavior
* Investigate failure cases and edge conditions

Key observations from testing:

* **93% advisory-grounded responses** (13/14 evaluation queries)
* **100% response coverage** through fallback retrieval
* **Zero hallucinations** on adversarial queries involving fake GHSA identifiers
* Successful identification of retrieval ranking limitations through trace analysis

Observability helped reveal situations where educational content could dominate retrieval despite relevant advisory information being available, leading to improvements in retrieval prioritization and source balancing.

---

# Data Sources

## Authoritative Sources

### GitHub Security Advisories (GHSA)

Official GitHub advisories containing:

* Vulnerability descriptions
* Affected packages
* Severity information
* Impact details
* Remediation guidance

These advisories are treated as the authoritative source of truth.

---

## Educational Sources

Curated security tutorials explaining vulnerability classes such as:

* SSRF (Server-Side Request Forgery)
* Path Traversal
* Command Injection
* ReDoS
* Prototype Pollution
* Client-Side Trust Boundary Issues

Educational content is used only to improve understanding and explain concepts.

---

# Indexed Vulnerabilities

The current knowledge base contains curated advisories covering:

| Vulnerability       | Category            |
| ------------------- | ------------------- |
| GHSA-fr5h-rqp8-mj6g | SSRF                |
| GHSA-5j98-mcp5-4vw2 | Command Injection   |
| GHSA-cpj6-fhp6-mr6j | Data Spoofing       |
| GHSA-grv7-fg5c-xmjg | ReDoS               |
| GHSA-mh29-5h37-fv8m | Prototype Pollution |
| GHSA-968p-4wvh-cqc8 | Regex Complexity    |
| GHSA-93m4-6634-74q7 | Path Traversal      |

---

# Retrieval Strategy

The system uses a hybrid retrieval pipeline.

## Phase 1: Advisory Retrieval

* Searches GitHub Security Advisory documents
* Prioritizes authoritative information
* Provides factual vulnerability details

## Phase 2: Educational Context Retrieval

* Retrieves tutorial content when relevant
* Adds conceptual explanations
* Improves learning and interpretability

Results are ranked using metadata-aware retrieval and source prioritization rather than simple keyword matching.

When advisory coverage is unavailable, the system gracefully falls back to educational content while avoiding fabricated security claims.

---

# Chunking Strategy

## GitHub Advisories

* Semantic document chunks
* Structured vulnerability information
* Metadata-rich indexing

## YouTube Tutorials

* Time-based chunks (~60 seconds)
* Context-aware segmentation
* Source attribution preserved

This hybrid chunking approach improves retrieval quality across fundamentally different document types.

---

# Example Query Types

### Vulnerability-Specific

```text
What is GHSA-grv7-fg5c-xmjg?
```

### Impact Analysis

```text
Which indexed vulnerabilities can lead to denial of service?
```

### Security Concepts

```text
How does prototype pollution differ from SQL injection?
```

### Adversarial Query

```text
What does GHSA-0000-0000-0000 describe?
```

The system avoids hallucination and responds appropriately when no supporting evidence exists.

---

# Challenges & Learnings

## Retrieval Quality Analysis

A major challenge was preventing educational content from dominating retrieval results.

LangSmith traces revealed situations where highly similar tutorial chunks ranked above more relevant advisory documents.

This led to improvements in:

* Retrieval filtering
* Source balancing
* Confidence signaling
* Graceful fallback behavior

---

## Transcript Ingestion

Challenges:

* Transcript availability
* API rate limits
* Chunk quality

Solutions:

* One-time ingestion pipeline
* Transcript chunking
* Curated video selection

---

## Small Dataset Bias

A curated dataset improves quality but increases the risk of limited coverage.

This was addressed through:

* Authority-first retrieval
* Explicit fallback behavior
* Conservative answer generation

---

# Tech Stack

## Frontend

* React

## Backend

* FastAPI

## RAG Framework

* LangChain

## Vector Database

* ChromaDB

## Embeddings

* HuggingFace Embeddings
* all-MiniLM-L6-v2

## LLM

* Gemini 2.5 Flash

## Observability

* LangSmith

## Data Sources

* GitHub Security Advisories API
* YouTube Transcript API

---

# Future Enhancements

* Expand curated vulnerability coverage
* Map advisories to OWASP Top 10 categories
* Improve semantic re-ranking
* Add automated retrieval evaluation
* Support CVE-to-GHSA correlation
* Introduce confidence-aware response generation

---

# Security Notes

* API keys are managed through environment variables.
* Generated databases and local artifacts are excluded from version control.
* Sensitive credentials are never committed to the repository.

See `.gitignore` for details.


---
