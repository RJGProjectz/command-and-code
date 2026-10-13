---
title: Fundamentals — Agentic AI Architectures & Tool Execution
type: entry
platforms:
  - Linux
languages:
  - Python
tasks:
  - Automation
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: advanced
tags:
  - ai
  - agentic-ai
  - tool-use
  - autonomous
---

# Fundamentals — Agentic AI Architectures & Tool Execution

Design patterns for autonomous AI agents capable of multi-step planning, tool invocation, environment perception, and feedback-loop self-correction.

An **agent** is a language model in a loop: it decides on an action, a tool runs it (search, run a query, call an API, edit a file), and the result is fed back to the model to decide the next step. Tools are usually described to the model as JSON schemas; protocols such as the Model Context Protocol (MCP) standardise how tools and data sources are connected.

## 1. ReAct (Reasoning + Acting) Cycle

```text
[Goal Input] ──► Thought (Reasoning) ──► Action (Tool Call) ──► Environment Execution
                       ▲                                              │
                       └──────── Observation (Result / Error) ────────┘
```

Other common patterns:

| Pattern | How it works | Use |
| --- | --- | --- |
| Plan-and-execute | Write a plan first, then run the steps | Long tasks that benefit from structure |
| Router | A model picks which specialised workflow or tool handles a request | Help desks, triage |
| Multi-agent | Several agents with different roles hand work to each other | Large tasks; harder to debug and to secure |
| Workflow with LLM steps | Fixed code calls the model only for specific steps | The most predictable option; prefer it when the steps are known |

## 2. Why agents change the risk

A chatbot can only say something wrong. An agent can **do** something wrong. Every tool result (a web page, an email, a ticket, a file) is untrusted input that can contain instructions — *indirect prompt injection* — and the model may follow them with the agent's permissions.

## 3. Security Safeguards for Autonomous Agents

- **Human-in-the-Loop (HITL)**: Mandatory manual confirmation gates for destructive state-changing actions (e.g., account termination, firewall drops, sending messages, payments).
- **Least privilege per tool**: separate read and write tools; scope credentials to the task and, where possible, to the user the agent acts for.
- **Execution Sandboxing**: Isolating tool execution within restricted containers with least-privilege filesystem and network boundaries (egress allow-lists stop data being sent to an attacker's server).
- **Structured outputs**: Enforcing strict JSON schema responses so tool arguments can be validated like any other input. This prevents malformed calls; it does not stop a model from choosing a harmful but well-formed action.
- **Trust labelling**: keep instructions from the operator separate from data the agent reads, and tell the model that retrieved content is data, not commands.
- **Limits**: maximum steps, time and spend per task, to stop loops.
- **Full audit trail**: log every tool call with its arguments and result, linked to the requesting user.

## 4. Security operations use

Typical, lower-risk starting points: summarising alerts, enriching indicators, drafting queries for an analyst to run, and writing incident timelines. Keep containment actions (isolating hosts, disabling accounts) behind an approval step until the agent's accuracy is measured.

## Related

- [OWASP Top 10 for LLMs](owasp-llm-top-10.md) (LLM01 Prompt Injection, LLM06 Excessive Agency)
- [Automated account containment](../tasks/automation/automated-account-containment.md)

## Sources

- [Yao et al. — ReAct: Synergizing Reasoning and Acting in Language Models](https://arxiv.org/abs/2210.03629)
- [Model Context Protocol specification](https://modelcontextprotocol.io/)
- [OWASP — LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
