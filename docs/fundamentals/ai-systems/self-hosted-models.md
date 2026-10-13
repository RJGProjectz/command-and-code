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
last_verified: 2026-10-12
difficulty: advanced
tags:
  - ai
  - ollama
  - vllm
  - air-gapped
---

# Fundamentals — Self-Hosted & Air-Gapped AI Model Runtimes

Deploying open-weights LLMs (Llama, Mistral, Qwen, Gemma) in private data centers or isolated cloud networks keeps prompts and data inside your own boundary.

Self-hosting removes one risk (sending data to a third party) and adds others: you now run, patch and secure the model server yourself.

## 1. Runtime Frameworks

- **vLLM**: High-throughput production serving with PagedAttention and continuous batching; OpenAI-compatible API.
- **Ollama**: Developer-friendly local model runner built on `llama.cpp` for Linux, macOS, and Windows; serves an HTTP API on port 11434.
- **llama.cpp**: C/C++ engine running quantised GGUF models on CPUs and consumer GPUs.
- **TGI (Text Generation Inference)**: Hugging Face serving engine supporting tensor parallelism.

## 2. Sizing in one line

Memory needed ≈ parameters × bytes per weight, plus room for the context (KV cache). A 7–8B model needs about 16 GB at 16-bit, or about 5 GB with 4-bit quantisation; a 70B model needs about 40 GB at 4-bit. Quantisation lowers quality somewhat, more at 4 bits and below.

## 3. Securing the runtime

| Risk | Control |
| --- | --- |
| Open API on the network (Ollama, vLLM and others have no authentication by default) | Bind to `127.0.0.1` (Ollama: `OLLAMA_HOST`), or put a reverse proxy with authentication and TLS in front; firewall the port |
| Malicious model files | Pull from trusted publishers only, check hashes, prefer `safetensors`/GGUF over pickle formats |
| Model management endpoints (pull, delete, create) | Do not expose them to users; only the inference endpoint |
| Prompt and output data | Log access, set retention, and treat logs as sensitive as the prompts |
| Outdated runtime | Patch like any other internet-facing service; runtimes have had remote code execution and path traversal bugs |

```bash
# Is the Ollama API exposed beyond this machine?
ss -ltnp | grep 11434            # want 127.0.0.1:11434, not 0.0.0.0 or *

# What models are installed (local API)
curl -s http://127.0.0.1:11434/api/tags
```

## 4. Air-gapped installs

Download the runtime and model files on a connected machine, verify the hashes, transfer them through your approved media process, and point the runtime at the local model directory. Disable automatic update checks and telemetry where the runtime has them.

## Related

- [LLM architecture](../ai-llm-architecture.md)
- [Vector databases](vector-databases.md)

## Sources

- [vLLM documentation](https://docs.vllm.ai/)
- [Ollama FAQ — exposing Ollama on the network](https://docs.ollama.com/faq)
- [llama.cpp](https://github.com/ggml-org/llama.cpp)
- [Hugging Face — Text Generation Inference](https://huggingface.co/docs/text-generation-inference/index)
