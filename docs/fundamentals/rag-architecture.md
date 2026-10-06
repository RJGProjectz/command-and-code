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
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - ai
  - rag
  - vector-db
  - embeddings
---

# Fundamentals — Retrieval-Augmented Generation (RAG) Architecture

Retrieval-Augmented Generation (RAG) grounds language models in authoritative external knowledge bases, preventing hallucinations and ensuring verifiable source attribution.

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

---

## 2. Core Operational Metrics

- **Chunk Size & Overlap**: Typical production balance: 500–1000 tokens per chunk with 10–15% overlap to preserve semantic continuity across boundaries.
- **Cosine Similarity vs Distance**: Measuring embedding proximity to rank relevance.
