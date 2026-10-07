---
title: Roadmap
type: index
hide:
  - navigation
  - toc
---

# Roadmap

Command & Code grows from real operational material, one phase at a time:

**document → standardize → connect → automate** — not *build complicated infrastructure → find a use for it later*.

<div class="cc-flow" markdown>

```text
FOUNDATION            ✅  ← Completed
    ↓
KNOWLEDGE EXPANSION   ✅  ← Completed (Fundamentals, Linux/Bash deep dive, ATT&CK sub-techniques, decision trees)
    ↓
AUTOMATION & TOOLING  ✅  ← Completed (71 production scripts cataloged, documented & Pester tested)
    ↓
API INTEGRATION       ✅  ← Completed (docs/apis/ operational across Graph, Defender, S1, Splunk, Webhooks)
    ↓
OPERATIONAL PLAYBOOKS ✅  ← Completed (10 IR playbooks, 10 investigation workflows, automated containment)
    ↓
LOCAL AI & SEARCH     🟡  ← Active (Local AI indexer tools/ai_indexer.py, offline lookup.py, RAG grounding)
    ↓
SECURITY TOOLKIT      ⚪  ← Future (Interactive command speed dial & query builders)
```

</div>

**Status key:** ✅ Complete · 🟡 In progress · 🔵 Planned · ⚪ Future

<div class="cc-phase" markdown>

## Phase 1 — Foundation

**Status:** ✅ Complete

**Objective:** a highly organised, searchable knowledge base with consistent metadata and CI.

**Key capabilities**

- [x] Repository structure, MkDocs + Material site, GitHub Actions build and Pages deploy
- [x] Platform / Language / Task navigation with generated browse tables
- [x] Search tuned with aliases and boosts
- [x] Metadata conventions and validation (`tools/cc.py`)
- [x] Windows, Linux, Microsoft 365 and virtualization reference entries
- [x] PowerShell, Bash, CMD, and Python language pages
- [x] KQL, SPL, S1QL and Sigma detection content; ATT&CK mapping
- [x] Incident-response, investigation, hunting and troubleshooting workflows
- [x] Initial toolbox scripts with documentation
- [x] Verify S1QL and environment-specific SPL content in production consoles
- [x] Publish to GitHub Pages

**Repository areas:** `docs/`, `scripts/`, `templates/`, `tools/`, `.github/workflows/`

</div>

<div class="cc-phase" markdown>

## Phase 2 — Knowledge Expansion

**Status:** ✅ Complete

**Objective:** move from *"what command do I use?"* to *"what am I trying to accomplish, what telemetry do I need, what query should I run, and what do I do with the result?"*

**Key capabilities**

- [x] Comprehensive **Fundamentals** category (Networking, Identity/IAM, Systems/OS Internals, Cloud Infrastructure, AI & LLM Systems, Web Apps/OWASP, GRC)
- [x] Deepened Linux platform guides (Firewalls/nftables, Storage/LVM, SELinux/AppArmor, Auditd, Kernel Tuning)
- [x] Deepened Bash language guides (Defensive Scripting, Error Handling & Traps, Raw Sockets, Modern CLI Ecosystem)
- [x] Windows CLI rebranded to CMD with cmd-native syntax
- [x] Expanded SPL, KQL, S1QL detection catalog (Brute force, SMB lateral movement, Agent tampering, MFA deletion)
- [x] Cross-platform troubleshooting decision trees (High CPU, Disk/Inode Exhaustion, TLS Handshake)
- [x] Deeper ATT&CK sub-technique relationships (Ransomware, Service Principal, MFA tampering, Kerberos)

**Repository areas:** `docs/platforms/`, `docs/detection/`, `docs/tasks/`, `docs/references/`, `docs/fundamentals/`

</div>

<div class="cc-phase" markdown>

## Phase 3 — Automation & Tooling Integration

**Status:** ✅ Complete

**Objective:** progressively import existing PowerShell, Bash and Python automation as documented, connected tools — not a dump of files.

**Key capabilities**

- [x] 71 sanitized production scripts cataloged in `scripts/powershell/`, `scripts/bash/`, `scripts/python/` and `docs/toolbox/`
- [x] Standardized tool blueprints (purpose, requirements, inputs, outputs, usage, security considerations)
- [x] Tool documentation pages for PowerShell, Bash, and Python toolboxes
- [x] Pester test suites for Active Directory and Azure Graph automation (`tests/powershell/`)

**Repository areas:** `scripts/`, `tests/`, `docs/toolbox/`

</div>

<div class="cc-phase" markdown>

## Phase 4 — API & Platform Integration

**Status:** ✅ Complete

**Objective:** practical, tested examples for security APIs, organised by the same Platform / Technology / Task model.

**Key capabilities**

- [x] Dedicated `docs/apis/` section operational
- [x] Microsoft Defender, Microsoft Graph, SentinelOne, Splunk, and Webhook APIs
- [x] OAuth 2.0 bearer token lifecycle and client credential authentication patterns
- [x] End-to-end webhook integration recipes (Slack, Microsoft Teams, Jira, ServiceNow)

```text
Microsoft Defender → Microsoft Graph → API → PowerShell / Python → Automation → Workflow
```

**Repository areas:** `docs/languages/*/rest-apis`, `docs/apis/`, `scripts/`

</div>

<div class="cc-phase" markdown>

## Phase 5 — Operational Playbooks

**Status:** ✅ Complete

**Objective:** end-to-end playbooks (alert → scope → contain → remediate → document) that link to entries rather than duplicating commands.

**Key capabilities**

- [x] 10 Incident Response Playbooks (Account Compromise, Ransomware Host Isolation, Azure Resource Hijacking, Service Principal Compromise, Phishing Email Triage, Malware Triage, SMB Lateral Movement, Suspicious Process/PowerShell)
- [x] 10 Investigation & Forensics Workflows (Suspicious IP, Device Forensics, User Identity Triage, Registry Persistence, Scheduled Tasks, Outbound C2)
- [x] Hypothesis-driven threat hunting workflows in Splunk and Defender
- [x] Automated containment runbooks bridging detection alerts to host isolation, token revocation, and IoC blocking

**Repository areas:** `docs/tasks/`, `templates/workflow.md`

</div>

<div class="cc-phase cc-active" markdown>

## Phase 6 — Intelligent Search & Local AI

**Status:** 🟡 In progress

**Objective:** a locally hosted assistant (e.g. Ollama or local AI daemon) grounded **only** in Command & Code content: natural-language search, command/query explanation, KQL ↔ SPL ↔ S1QL starting points, related-procedure discovery.

**Key capabilities**

- [x] Offline CLI semantic lookup utility (`tools/lookup.py`)
- [x] Structured RAG knowledge indexer (`tools/ai_indexer.py` producing `site/ai_knowledge_index.jsonl`)
- [ ] Grounding connector for local Ollama / AI daemon embedding workflows
- [ ] Natural language query translation into KQL / SPL / S1QL

**Repository areas:** `tools/ai_indexer.py`, `tools/lookup.py`, `site/ai_knowledge_index.jsonl`

</div>

<div class="cc-phase" markdown>

## Phase 7 — Operational Security Toolkit

**Status:** ⚪ Future

**Objective:** interactive workflows, query builders and translators, posture checks and automated reporting — built on top of the documentation, which remains the foundation.

</div>

## Knowledge ingestion model

How existing work enters Command & Code:

```text
Existing work
    → Extract (commands, queries, code, APIs, configuration, procedures, lessons learned)
    → Classify (platform, technology, task)
    → Connect (related commands, queries, scripts, workflows, references)
    → Command & Code
```

Two layers, connected over time:

| Knowledge layer | Operational layer |
| --- | --- |
| Commands · queries · configuration · procedures · references | Scripts · automation · APIs · tools · workflows · integrations |

```text
KQL query → detection → investigation workflow → PowerShell collection script → Graph API → report
```

*Update this page by editing `docs/roadmap.md` — change a phase's status emoji and tick its checklist.*
