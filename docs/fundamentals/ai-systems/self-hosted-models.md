---
title: Fundamentals — Self-Hosted & Air-Gapped AI Model Runtimes
type: entry
platforms:
  - Linux
languages:
  - Bash
  - Python
tasks:
  - Hardening
  - Automation
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - ai
  - ollama
  - vllm
  - air-gapped
---

# Fundamentals — Self-Hosted & Air-Gapped AI Model Runtimes

Deploying open-weights LLMs (Llama 3, Mistral, Qwen) in private enterprise data centers or isolated cloud VPCs eliminates data exfiltration risks.

## 1. Runtime Frameworks

- **vLLM**: High-throughput production serving with PagedAttention and continuous batching.
- **Ollama**: Developer-friendly local model runner wrapping `llama.cpp` for Linux, macOS, and Windows.
- **TGI (Text Generation Inference)**: Hugging Face optimized serving engine supporting tensor parallelism.
