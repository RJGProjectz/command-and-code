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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - ai
  - vector-db
  - hnsw
  - chroma
---

# Fundamentals — Vector Databases & Approximate Nearest Neighbors (ANN)

Vector databases (Qdrant, Chroma, Milvus, pgvector) index high-dimensional embeddings to perform fast similarity lookups over millions of document chunks.

Comparing a query against every stored vector (exact search) is accurate but slow at scale. **Approximate nearest neighbour (ANN)** indexes trade a little recall for a large speed-up.

## 1. Indexing Algorithms

- **HNSW (Hierarchical Navigable Small World)**: Graph-based indexing offering high recall and fast query times by building multi-layer proximity graphs. Uses more memory; the default in most vector databases.
- **IVF (Inverted File Index)**: Partitions vector space into clusters (Voronoi cells) and searches only the closest few. Less memory; recall depends on how many clusters you probe.
- **Quantisation (PQ, scalar, binary)**: Compresses vectors to save memory, at some cost in accuracy. Often combined with IVF or HNSW.

## 2. Choosing a store

| Option | Fits |
| --- | --- |
| **pgvector** (PostgreSQL extension) | You already run PostgreSQL; moderate scale; want SQL filters and transactions |
| **Chroma** | Prototypes and small local projects; embedded in Python |
| **Qdrant**, **Milvus**, **Weaviate** | Dedicated service; large collections; payload filtering and hybrid search |
| Managed search (Azure AI Search, OpenSearch, Elasticsearch) | Need keyword + vector (hybrid) search in one place |

Every entry is a **vector plus metadata** (source document, section, date, access labels). Filtering on metadata is what makes permission-aware search possible.

## 3. Operating it securely

- **Authentication on**: several vector databases run with no authentication by default and listen on all interfaces. Bind to localhost or a private network and enable API keys or TLS.
- **Access control at query time**: store the document's access labels as metadata and filter by the requesting user's rights; never return a chunk the user could not open in the original system.
- **Data lifecycle**: when a source document is deleted or its permissions change, update the index too, or the old content stays searchable.
- **Backups and encryption**: the stored chunks are a copy of the source text; protect them the same way.
- **Ingestion control**: log who adds documents; a planted document can inject instructions into every answer that retrieves it.

## Related

- [Tokenization and embeddings](tokenization-embeddings.md)
- [RAG architecture](../rag-architecture.md)
- [Self-hosted models](self-hosted-models.md)

## Sources

- [Malkov & Yashunin — HNSW paper](https://arxiv.org/abs/1603.09320)
- [pgvector README](https://github.com/pgvector/pgvector)
- [Qdrant documentation — Security](https://qdrant.tech/documentation/guides/security/)
