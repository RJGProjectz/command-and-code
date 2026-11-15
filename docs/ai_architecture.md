# AI Architecture - Command & Code
> Created: 2026-11-15T00:00:00Z
> Author: RJGProjectz

This document describes the AI-powered knowledge retrieval architecture for Command & Code.

---

## 1. System Overview

### Hybrid Knowledge Stack

The system combines three layers:

**Layer 1 - Static Documentation (Public)**
- 490 pages across Foundations, Offensive, Defensive, Reference
- GitHub Pages hosted at rjgprojectz.github.io/command-and-code/
- Fast indexed lookup via mkdocs material search

**Layer 2 - PDF Vector Store (Private)**
- 42 cybersecurity books ingested (~831 MB total)
- Stored in ChromaDB vector database locally
- Copyright-compliant: private RAG only, never published
- Semantic search using Ollama nomic-embed-text embeddings

**Layer 3 - AI Grounding (cc ask)**
- Ollama llama3.2 model on localhost:11434
- Zero cloud calls, all processing local
- Merges results from Layer 1 and 2
- Generates grounded answers with citations

---

## 2. Query Flow Diagram

                    +------------------+
                    |    User Question |
                    +--------+---------+
                             |
                             v
                    +--------v---------+
                    |   Route Query    |
                    | (static vs PDF)  |
                    +--------+---------+
                             |
               +-------------+-------------+
               |                           |
               v                           v
    +------------------+        +-------------------+
    | Retrieve Static  |        | Retrieve Embeddings|
    | Pages (mkdocs)   |        | ChromaDB search    |
    +--------+---------+        +--------+----------+
             |                          |
             +-------------+------------+
                           |
                           v
                    +--------v---------+
                    | Merge Results    |
                    | Deduplicate      |
                    +--------+---------+
                             |
                             v
                    +--------v---------+
                    | Generate Answer  |
                    | with Citations   |
                    +-------------------+

---

## 3. Component Architecture

### 3.1 PDF Ingestion Pipeline

```
tools/pdf_ingest.py
- Input: PDFs/ directory (42 books)
- Extract: PyMuPDF full-text per page
- Chunk: 512-token sliding window (64-token overlap)
- Embed: Ollama nomic-embed-text model
- Store: ChromaDB persistent collection at data/chromadb/books/
- Gitignored: never committed to repo
```

### 3.2 AI Grounding Engine

```
tools/ai_grounding.py
- Input: user query string
- Query Layer 1: mkdocs search index (static pages)
- Query Layer 2: ChromaDB vector store (PDF embeddings)
- Merge: combine results, deduplicate by topic
- Rank: relevance scoring across both sources
- Generate: llama3.2 grounded response with citations
- Output: markdown answer with [source, page N] citations
```

### 3.3 CLI Interface

```
tools/cc_ask.py
python cc.py ask "<question>"
Options: --books-only (PDF only), --site-only (static pages)
Output: formatted markdown with inline citations
```

---

## 4. Evaluation Metrics

| Metric | Static Only | PDF Merged | Target |
|--------|-------------|------------|--------|
| Hit@1  | 62%         | 88%        | >=90%  |
| Hit@5  | 84%         | 100%       | 100%   |
| MRR    | 0.72        | 0.94       | >=0.8  |

CI gate blocks merges when eval < target.

---

## 5. Security & Compliance

### Copyright Constraints

- All 42 books are commercial titles (Packt, O'Reilly, No Starch)
- Publisher licenses prohibit:
  - Verbatim reproduction in public repositories
  - Distribution of extracted content to third parties
  
**Permitted uses:**
- Private local vector store for personal RAG queries
- Original summaries with citations (no direct copying)
- Research material for authoring KB pages

### Data Flow Security

```
+------------------+      +-------------------+
| PDFs/ (local)    |--->  | PyMuPDF extract   |
+------------------+      +--------+----------+
                                   |
                                   v
                    +---------------v--------------+
                    | ChromaDB (gitignored, private)|
                    +-------------+----------------+
                                 |
                                 v
            +--------------------v-------------+
            | Ollama llama3.2 localhost:11434  |
            | Zero cloud calls                 |
            +----------------------------------+
```

No data leaves the machine.

---

## 6. Integration with Existing Site

### Workflow

1. User asks question via terminal or web UI
2. cc ask routes to appropriate knowledge source(s)
3. AI grounds answer in cited sources
4. Answer displayed with citations [page N], [Book Title, p.N]

### Advantages

- **Completeness**: 5,000+ pages of KB + 42 books searchable
- **Grounding**: Every answer cites exact source
- **Privacy**: PDF content never published publicly
- **Flexibility**: Toggle between site-only and PDF-only queries

---

## 7. Roadmap

### Phase 1: Current (Nov 2026)

- [x] ChromaDB vector store implemented
- [x] ai_grounding.py with dual-source retrieval
- [x] Evaluation suite (hit@1/5, MRR)
- [ ] CC ask CLI integration (WP-11 done)

### Phase 2: PDF Authoring Loop

- Batch processing of 7,664 gap topics
- Query ChromaDB for technique/commands during authoring
- Generate KB pages with citations to source books

### Phase 3: Advanced Features

- Multi-turn conversational RAG
- Cross-book synthesis queries
- Automatic table of contents from PDFs

---

## A. Technical Specifications

### Embedding Model

- **Model**: nomic-embed-text (via Ollama)
- **Dimensions**: 768
- **Context**: ~8k tokens
- **Host**: localhost:11434
- **API**: /api/embeddings

### ChromaDB Configuration

```python
chroma_client = chromadb.PersistentClient(
    path="data/chromadb/books"
)
collection = chroma_client.create_collection(
    name="cybersecurity_books",
    metadata={"hnsw:space": "cosine"}
)
```

### Citation Format

- Static pages: `[page N]` (e.g., [12])
- PDF books: `[Book Title, p.N]` (e.g., [Blue Team Handbook, p.45])
- Multiple sources: cited in order of relevance

---

## B. Operations Checklist

### Pre-deployment

- [ ] ChromaDB data directory gitignored
- [ ] Ollama running with embedding model loaded
- [ ] Evaluation suite passing CI gate
- [ ] Copyright notice in README

### Maintenance

- Periodic re-embedding if source PDFs update
- Monitor vector store size (target: <2GB)
- Review citation accuracy quarterly

---

**Author**: RJGProjectz  
**Last Updated**: 2026-11-15
