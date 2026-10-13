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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - ai
  - tokenization
  - embeddings
  - vectors
---

# Fundamentals — Tokenization & Vector Embeddings in AI

Tokenization breaks unstructured text into atomic processing units, while embedding models project tokens into high-dimensional vector spaces capturing semantic meaning.

## 1. Tokens

Models do not read characters or words; they read **tokens**, pieces of text from a fixed vocabulary built with algorithms such as BPE (byte-pair encoding), WordPiece or SentencePiece. Common words are one token; rare words, code, IP addresses, hashes and non-English text split into several.

| Text | Roughly |
| --- | --- |
| English prose | about 4 characters, or ¾ of a word, per token |
| `powershell.exe -enc SQBFAFgA...` | Base64 and hashes are token-hungry: often 2–3 characters per token |
| JSON logs | Keys, quotes and braces all cost tokens |

Why it matters in practice: context limits, cost and speed are all counted in tokens, so sending raw logs to a model is expensive. Pre-filter and summarise first.

## 2. Mathematical Principle of Vector Embeddings

An embedding model maps a piece of text to a fixed-length list of numbers (a vector). The size depends on the model: OpenAI `text-embedding-3-small` produces 1,536 dimensions, `text-embedding-3-large` 3,072, and the open `nomic-embed-text` 768.

```text
"failed logon from unknown IP"   ->  [0.024, -0.185, 0.491, ..., -0.012]
```

Semantic similarity is computed using **cosine similarity**, the cosine of the angle between two vectors:

```text
cos(θ) = (A · B) / (|A| × |B|)
```

Texts with similar meaning point in similar directions and score close to `1.0`, even with no keywords in common ("account lockout" and "too many bad passwords"). Unrelated texts score near `0`.

```python
import math

def cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))

print(round(cosine([1, 2, 3], [2, 4, 6]), 3))   # 1.0: same direction
```

## 3. Practical rules

- **Use the same embedding model** for indexing and for queries; vectors from different models are not comparable.
- **Re-embed everything** when you change models.
- Embeddings capture meaning, not exact strings. Searching for a specific hash, CVE or event ID works better with keyword search; combine both (hybrid search).
- Embeddings can leak information about the source text, so treat a vector store with the same sensitivity as the documents it was built from.

## Related

- [Vector databases](vector-databases.md)
- [RAG architecture](../rag-architecture.md)
- [LLM architecture](../ai-llm-architecture.md)

## Sources

- [OpenAI — Embeddings guide (model dimensions)](https://platform.openai.com/docs/guides/embeddings)
- [Hugging Face — Summary of the tokenizers](https://huggingface.co/docs/transformers/tokenizer_summary)
- [Nomic — nomic-embed-text model card](https://huggingface.co/nomic-ai/nomic-embed-text-v1.5)
