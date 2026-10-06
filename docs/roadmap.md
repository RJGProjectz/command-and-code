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
KNOWLEDGE EXPANSION   🟡  ← Mature (Fundamentals, Linux/Bash deep dive, multi-platform references)
    ↓
AUTOMATION & TOOLING  🟡  ← Active (66+ production scripts cataloged & documented)
    ↓
API INTEGRATION       🟡  ← Active (docs/apis/ operational across Graph, Defender, S1, Splunk)
    ↓
OPERATIONAL PLAYBOOKS 🟡  ← Active (10 incident response playbooks & 10 investigation workflows)
    ↓
LOCAL AI              ⚪  ← Future (Local Ollama / RAG assistant)
    ↓
SECURITY TOOLKIT      ⚪  ← Future (Interactive command wall & query builders)
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

<div class="cc-phase cc-active" markdown>

## Phase 2 — Knowledge Expansion

**Status:** 🟡 In progress

**Objective:** move from *"what command do I use?"* to *"what am I trying to accomplish, what telemetry do I need, what query should I run, and what do I do with the result?"*

**Key capabilities**

- [x] Comprehensive **Fundamentals** category (Networking, Identity/IAM, Systems/OS Internals, Cloud Infrastructure, AI & LLM Systems)
- [x] Deepened Linux platform guides (Firewalls/nftables, Storage/LVM, SELinux/AppArmor, Auditd, Kernel Tuning)
- [x] Deepened Bash language guides (Defensive Scripting, Error Handling & Traps, Raw Sockets, Modern CLI Ecosystem)
- [x] Windows CLI rebranded to CMD with cmd-native syntax
- [x] Expanded SPL, KQL, S1QL detection catalog (Brute force, SMB lateral movement, Agent tampering, MFA deletion)
- [ ] Cross-platform troubleshooting decision trees
- [ ] Deeper ATT&CK sub-technique relationships

**Repository areas:** `docs/platforms/`, `docs/detection/`, `docs/tasks/`, `docs/references/`, `docs/fundamentals/`

</div>

<div class="cc-phase" markdown>

## Phase 3 — Automation & Tooling Integration

**Status:** 🟡 In progress

**Objective:** progressively import existing PowerShell, Bash and Python automation as documented, connected tools — not a dump of files.

**Key capabilities**

- [x] 66+ sanitized production scripts cataloged in `scripts/powershell/` and `docs/toolbox/`
- [x] Standardized tool blueprints (purpose, requirements, inputs, outputs, usage, security considerations)
- [x] Tool documentation pages for PowerShell, Bash, and Python toolboxes
- [ ] Pester test suites for all Active Directory and Azure Graph automation

**Repository areas:** `scripts/`, `docs/toolbox/`

</div>

<div class="cc-phase" markdown>

## Phase 4 — API & Platform Integration

**Status:** 🟡 In progress

**Objective:** practical, tested examples for security APIs, organised by the same Platform / Technology / Task model.

**Key capabilities**

- [x] Dedicated `docs/apis/` section operational
- [x] Microsoft Defender, Microsoft Graph, SentinelOne, Splunk, and Webhook APIs
- [x] OAuth 2.0 bearer token lifecycle and client credential authentication patterns
- [ ] End-to-end webhook integration recipes (Slack, Microsoft Teams, Jira)

```text
Microsoft Defender → Microsoft Graph → API → PowerShell / Python → Automation → Workflow
```

**Repository areas:** `docs/languages/*/rest-apis`, `docs/apis/`, `scripts/`

</div>

<div class="cc-phase" markdown>

## Phase 5 — Operational Playbooks

**Status:** 🟡 In progress

**Objective:** end-to-end playbooks (alert → scope → contain → remediate → document) that link to entries rather than duplicating commands.

**Key capabilities**

- [x] 10 Incident Response Playbooks (Account Compromise, Ransomware Host Isolation, Azure Resource Hijacking, Service Principal Compromise, Phishing Email Triage, Malware Triage, SMB Lateral Movement, Suspicious Process/PowerShell)
- [x] 10 Investigation & Forensics Workflows (Suspicious IP, Device Forensics, User Identity Triage, Registry Persistence, Scheduled Tasks, Outbound C2)
- [x] Hypothesis-driven threat hunting workflows in Splunk and Defender
- [ ] Automated containment runbooks bridging detection alerts to remediation scripts

**Repository areas:** `docs/tasks/`, `templates/workflow.md`

</div>

<div class="cc-phase" markdown>

## Phase 6 — Intelligent Search & Local AI

**Status:** ⚪ Future

**Objective:** a locally hosted assistant (e.g. Ollama) grounded **only** in Command & Code content: natural-language search, command/query explanation, KQL ↔ SPL ↔ S1QL starting points, related-procedure discovery.

The repository is already structured for this: consistent front matter, one topic per page, task-phrased headings and separate scripts make it straightforward to index.

**Repository areas:** future `tools/index/`; no changes to content format required

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
