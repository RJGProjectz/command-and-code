---
title: Fundamentals — Tokenization & Vector Embeddings in AI
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
  - tokenization
  - embeddings
  - vectors
---

# Fundamentals — Tokenization & Vector Embeddings in AI

Tokenization breaks unstructured text into atomic processing units, while embedding models project tokens into high-dimensional vector spaces capturing semantic meaning.

## 1. Mathematical Principle of Vector Embeddings

An embedding model (e.g., `text-embedding-3-large`, `nomic-embed-text`) maps a phrase into a float vector array (e.g. 1536 or 3072 dimensions):

$$\vec{A} = [0.024, -0.185, 0.491, \dots, -0.012]$$

Semantic similarity is computed using **Cosine Similarity**:

$$\cos(\theta) = \frac{\vec{A} \cdot \vec{B}}{\|\vec{A}\| \|\vec{B}\|}$$

Phrases with similar conceptual meanings produce scores close to `1.0`, even with zero overlapping keywords.
