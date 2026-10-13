---
title: Fundamentals — LLM Architecture & Inference Engineering
type: entry
platforms:
  - Linux
languages:
  - Python
tasks:
  - Hardening
  - Automation
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - ai
  - llm
  - transformer
  - architecture
---

# Fundamentals — LLM Architecture & Inference Engineering

Architectural breakdown of modern Large Language Models (LLMs), tokenization mechanics, and enterprise inference runtime security.

## 1. Transformer Core Components

- **Tokenization**: Converting raw unicode text into integer token IDs (e.g. BPE, WordPiece, SentencePiece).
- **Embeddings**: Each token ID is mapped to a vector; position information is added so word order matters.
- **Self-Attention Mechanism**: Enables tokens to dynamically weight contextual relationships across long context windows.
- **Inference Pipeline**: Text input → Tokenization → Embeddings → Forward Pass (Layers) → Logits → Sampling (Temperature / Top-P) → Detokenization.

The model produces **one token at a time**: each new token is appended to the input and the forward pass runs again. That is why output speed is measured in tokens per second, and why long prompts and long answers both cost time and money.

## 2. Terms that matter in practice

| Term | Meaning | Why you care |
| --- | --- | --- |
| Context window | Maximum tokens of input + output the model can handle at once | Logs, documents and conversation history must fit; the excess is cut off or must be summarised |
| Temperature / Top-P | How random the sampling is | Low (0–0.3) for repeatable extraction and classification; higher for drafting |
| System prompt | Instructions placed before the user's input | Guides behaviour but is **not a security boundary** (see prompt injection) |
| Quantisation | Storing weights in fewer bits (8, 4) | Lets large models run on smaller GPUs with some quality loss |
| KV cache | Stored attention state for tokens already processed | Main memory cost when serving many users or long contexts |
| Hallucination | Fluent output that is not true | Verify facts, commands and package names before use |

## 3. Enterprise Deployment Security

- **Air-Gapped / Self-Hosted Inference**: Utilizing Ollama, vLLM, or TGI behind internal API reverse proxies keeps sensitive data away from third-party providers (see [self-hosted models](ai-systems/self-hosted-models.md)).
- **API Guardrails**: Intercepting prompts and completions to detect prompt injection, block sensitive data leaving, and enforce output schemas. Guardrails reduce risk; they do not remove it.
- **Authentication and quotas** on the inference API: model servers often ship with no authentication, and an open endpoint is free compute for anyone who finds it.
- **Logging**: record who sent which prompt, which tools were called and what came back, with retention and access rules that match the sensitivity of the data.
- **Model provenance**: download weights only from trusted publishers, check hashes, and prefer the `safetensors` format over pickle-based files, which can execute code when loaded.

## Related

- [OWASP Top 10 for LLMs](owasp-llm-top-10.md)
- [Tokenization and embeddings](ai-systems/tokenization-embeddings.md)
- [Agentic AI](agentic-ai.md)

## Sources

- [Vaswani et al. — Attention Is All You Need (2017)](https://arxiv.org/abs/1706.03762)
- [Hugging Face — Transformers documentation](https://huggingface.co/docs/transformers/index)
- [Hugging Face — safetensors](https://huggingface.co/docs/safetensors/index)
