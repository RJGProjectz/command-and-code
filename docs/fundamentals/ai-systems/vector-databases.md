---
title: Fundamentals — Vector Databases & Approximate Nearest Neighbors (ANN)
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
  - vector-db
  - hnsw
  - chroma
---

# Fundamentals — Vector Databases & Approximate Nearest Neighbors (ANN)

Vector databases (Qdrant, Chroma, Milvus, pgvector) index high-dimensional embeddings to perform sub-millisecond similarity lookups over millions of document chunks.

## 1. Indexing Algorithms

- **HNSW (Hierarchical Navigable Small World)**: Graph-based indexing offering high recall and fast query times by building multi-layer proximity graphs.
- **IVF (Inverted File Index)**: Partitions vector space into Voronoi cells to narrow query sweeps.
