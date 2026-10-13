---
title: Fundamentals — OWASP Top 10 for Large Language Models
type: entry
platforms:
  - Linux
languages:
  - Python
tasks:
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - ai
  - owasp
  - security
  - llm-top-10
aliases: [Data Poisoning]
---

# Fundamentals — OWASP Top 10 for Large Language Models

Standardized security risks and vulnerability taxonomy for enterprise LLM applications and agentic systems.

This is the **2025** edition of the OWASP Top 10 for LLM Applications. It replaced the 2023 list (v1.1): *Insecure Output Handling* became *Improper Output Handling*, *Model Denial of Service* became *Unbounded Consumption*, and *System Prompt Leakage*, *Vector and Embedding Weaknesses* and *Misinformation* were added.

| ID | Vulnerability Title | Attack Mechanism | Main mitigations |
| :--- | :--- | :--- | :--- |
| **LLM01** | **Prompt Injection** | Instructions hidden in user input or in content the model reads (web pages, emails, documents) change its behaviour | No complete fix exists. Treat model output as untrusted, give the model least privilege, separate and label untrusted content, require human approval for consequential actions |
| **LLM02** | **Sensitive Information Disclosure** | The model reveals PII, secrets or confidential data from its context, training data or connected systems | Do not put secrets in prompts; filter what is retrieved by the *user's* permissions; output DLP |
| **LLM03** | **Supply Chain** | Compromised models, weights, datasets, plug-ins or libraries (including malicious pickle files) | Use trusted sources, verify hashes/signatures, prefer `safetensors`, keep an AI bill of materials |
| **LLM04** | **Data and Model Poisoning** | Tampered training, fine-tuning or embedding data plants backdoors or biases | Provenance of data, review fine-tuning sets, test models for trigger behaviour |
| **LLM05** | **Improper Output Handling** | Model output is passed unchecked to a shell, SQL, browser (XSS) or another system | Validate and encode output like any user input; parameterised queries; strict schemas |
| **LLM06** | **Excessive Agency** | An agent has more tools, permissions or autonomy than its task needs, so an injection turns into real damage | Minimal tools and scopes, per-user credentials, human approval for state changes |
| **LLM07** | **System Prompt Leakage** | Attackers extract the system prompt and learn internal rules, or secrets put there | Never rely on the system prompt for security; no credentials in prompts |
| **LLM08** | **Vector and Embedding Weaknesses** | RAG stores leak data across tenants or users, or accept poisoned documents | Permission-aware retrieval, tenant isolation, vetted ingestion |
| **LLM09** | **Misinformation** | Confident but wrong output (hallucinated facts, packages, commands) is trusted | Grounding with citations, human review for critical use, verify suggested packages exist |
| **LLM10** | **Unbounded Consumption** | Excessive requests or huge inputs exhaust capacity or budget ("denial of wallet"), or extract the model | Rate limits, input/output size limits, quotas, monitoring per user |

## Applying it

- **Threat-model the data flows**, not just the model: what untrusted content reaches the prompt, and what tools or systems the output can reach. The dangerous combination is *untrusted input* + *access to private data* + *a way to send data out*.
- **Log prompts, tool calls and outputs** (with privacy controls) so incidents can be investigated.
- **Red-team before release**: test prompt injection through every input channel, including retrieved documents and tool results.

## Related

- [Agentic AI architectures](agentic-ai.md)
- [RAG architecture](rag-architecture.md)
- [Prompt engineering and guardrails](ai-systems/prompt-engineering.md)

## Sources

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS — adversarial threat landscape for AI systems](https://atlas.mitre.org/)
- [NIST AI 600-1 — Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
