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
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - ai
  - owasp
  - security
  - llm-top-10
---

# Fundamentals — OWASP Top 10 for Large Language Models

Standardized security risks and vulnerability taxonomy for enterprise LLM applications and agentic systems.

| ID | Vulnerability Title | Attack Mechanism & Mitigation |
| :--- | :--- | :--- |
| **LLM01** | **Prompt Injection** | Manipulating model instructions via untrusted inputs. Mitigate via delimiter tagging and strict input sanitization. |
| **LLM02** | **Insecure Output Handling** | Executing raw LLM output in backend shells or browsers. Mitigate via strict schema validation. |
| **LLM03** | **Training Data Poisoning** | Tampering with training/fine-tuning datasets to introduce backdoors. |
| **LLM04** | **Model Denial of Service** | Resource-intensive context exhaustion attacks. Enforce rate limiting and context bounds. |
| **LLM05** | **Supply Chain Vulnerabilities** | Compromised base models or unvetted third-party plugins. |
| **LLM06** | **Sensitive Information Disclosure** | Leaking confidential training data or PII in completions. Enforce DLP scrubbing. |
