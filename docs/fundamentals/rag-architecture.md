---
title: Fundamentals — Retrieval-Augmented Generation (RAG) Architecture
type: entry
platforms:
  - Linux
languages:
  - Python
tasks:
  - Automation
  - Investigation
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - ai
  - rag
  - vector-db
  - embeddings
---

# Fundamentals — Retrieval-Augmented Generation (RAG) Architecture

Retrieval-Augmented Generation (RAG) grounds language models in authoritative external knowledge bases, reducing hallucinations and enabling verifiable source attribution.

Instead of relying on what the model memorised during training, RAG searches your own documents at question time and puts the most relevant passages into the prompt. The model then answers from those passages and can cite them. It does not eliminate wrong answers: the retrieval can miss the right passage, and the model can still misread what it was given.

## 1. Pipeline Stages

```text
[Documents] ──► Chunking ──► Embedding Model ──► Vector Database (Chroma, Qdrant)
                                                        │
[User Query] ──► Embedding Model ──► Semantic Search ───┘
                                           │
                                    Top-K Chunks
                                           │
                                           ▼
[LLM Context Prompt] ◄── User Query + Context Chunks
       │
       ▼
[Grounded Answer with Sources]
```

## 2. Core Operational Metrics

- **Chunk Size & Overlap**: A common starting point is a few hundred to about 1,000 tokens per chunk with 10–15% overlap to preserve continuity across boundaries. Split on document structure (headings, sections) rather than fixed character counts where possible.
- **Cosine Similarity vs Distance**: Measuring embedding proximity to rank relevance (see [tokenization and embeddings](ai-systems/tokenization-embeddings.md)).
- **Top-K**: how many chunks go into the prompt. Too few misses context; too many dilutes it and costs tokens.

## 3. What makes RAG work well

| Technique | Problem it solves |
| --- | --- |
| **Hybrid search** (keyword/BM25 + vectors) | Vectors alone miss exact identifiers: event IDs, CVE numbers, command names |
| **Re-ranking** | A second model re-orders the top results by actual relevance |
| **Metadata filters** | Restrict to a product, date range or document type before searching |
| **Citations in the answer** | Users can check the source; ungrounded claims stand out |
| **Evaluation set** | A fixed list of questions with known answers to measure changes |

## 4. Security of RAG systems

- **Permission-aware retrieval**: filter results by what the *asking user* may read, at query time. Otherwise RAG becomes a way to read documents you have no access to (OWASP LLM08).
- **Poisoned documents**: anyone who can add a document to the index can plant instructions (indirect prompt injection) or false facts. Control and log who can ingest content.
- **Sensitive data in the index**: embeddings and stored chunks are copies of the original data; protect and delete them like the source.
- **Tenant isolation** in multi-tenant systems: separate collections or enforced filters, never "trust the prompt" to keep tenants apart.

## Related

- [Vector databases](ai-systems/vector-databases.md)
- [OWASP Top 10 for LLMs](owasp-llm-top-10.md)
- [LLM architecture](ai-llm-architecture.md)

## Sources

- [Lewis et al. — Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks](https://arxiv.org/abs/2005.11401)
- [OWASP — LLM08:2025 Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
