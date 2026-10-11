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
AUTOMATION & TOOLING  ✅  ← Completed (71 production scripts cataloged & documented; Pester suites for AD & Graph)
    ↓
API INTEGRATION       ✅  ← Completed (docs/apis/ operational across Graph, Defender, S1, Splunk, Webhooks)
    ↓
OPERATIONAL PLAYBOOKS ✅  ← Completed (10 IR playbooks, 10 investigation workflows, automated containment)
    ↓
LOCAL AI & SEARCH     ✅  ← Completed (Local AI indexer, grounding assistant tools/ai_grounding.py, RAG)
    ↓
VALIDATION & GRC      ✅  ← Completed (MITRE ATT&CK STIX validator, OpenAPI specs, CISA SCuBA, LOLBAS audit)
    ↓
PRACTITIONER EXP      ✅  ← Completed (Command Builder, Diagnostic Decision Trees, Terminal CLI cc)
    ↓
THREAT HUNTING        ✅  ← Completed (Hypothesis framework, LFO baselining, cross-platform behavior, cloud LOTC, hunt runner)
    ↓
THREAT INTELLIGENCE   ✅  ← Completed (STIX/TAXII pipeline, adversary emulation, IoC lifecycle, threat actor profiles, CTI gap analyzer)
    ↓
QUALITY & VERIFICATION 🟡  ← In progress (lint in CI, contract tests for every PowerShell script; pytest next)
    ↓
LOCAL AI ASSISTANT v2  🔵  ← Planned (grounded `cc ask` with citations and an evaluation set)
    ↓
WEBSITE UX/UI REFACTOR 🔵  ← Planned (navigation, landing pages, mobile and search usability)
```

</div>

**Status key:** ✅ Complete · 🟡 In progress · 🔵 Planned · ⚪ Future

<div class="cc-phase" markdown>

## Phase 1 — Foundation

**Status:** ✅ Complete

**Objective:** a highly organized, searchable knowledge base with consistent metadata and CI.

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
- [x] Pester test suites for Active Directory and Azure Graph automation (`tests/powershell/`; run in CI since 2026-10-11 — every script now covered by the Phase 11 contract suite)

**Repository areas:** `scripts/`, `tests/`, `docs/toolbox/`

</div>

<div class="cc-phase" markdown>

## Phase 4 — API & Platform Integration

**Status:** ✅ Complete

**Objective:** practical, tested examples for security APIs, organized by the same Platform / Technology / Task model.

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

<div class="cc-phase" markdown>

## Phase 6 — Intelligent Search & Local AI

**Status:** ✅ Complete

**Objective:** a locally hosted assistant (e.g. Ollama or local AI daemon) grounded **only** in Command & Code content: natural-language search, command/query explanation, KQL ↔ SPL ↔ S1QL starting points, related-procedure discovery.

**Key capabilities**

- [x] Offline CLI semantic lookup utility (`tools/lookup.py`)
- [x] Structured RAG knowledge indexer (`tools/ai_indexer.py` producing `site/ai_knowledge_index.jsonl`)
- [x] Grounding connector for local Ollama / AI daemon embedding workflows (`tools/ai_grounding.py`)
- [x] Natural language query translation into KQL / SPL / S1QL
- [x] Offline prompt synthesizer injecting verified code blocks directly into LLM context

**Repository areas:** `tools/ai_indexer.py`, `tools/lookup.py`, `tools/ai_grounding.py`, `site/ai_knowledge_index.jsonl`

</div>

<div class="cc-phase" markdown>

## Phase 7 — Authoritative Validation & Compliance Benchmarking

**Status:** ✅ Complete

**Objective:** continuously validate operational coverage, query syntax, and hardening recommendations against authoritative external industry frameworks (MITRE ATT&CK STIX 2.1, OpenAPI/Swagger specifications, CIS Benchmarks Level 1/2, CISA SCuBA, and DISA STIGs).

**Key capabilities**

- [x] MITRE ATT&CK STIX 2.1 automated coverage engine (`tools/validate_mitre.py`)
- [x] Automated MITRE ATT&CK Navigator Layer generation (`site/mitre_attack_coverage.json`)
- [x] Cross-platform ATT&CK technique reference matrix (`docs/references/mitre-attack-matrix.md`)
- [x] Automated OpenAPI / Swagger schema validator for Graph, Defender, SentinelOne, and Splunk REST APIs (`tools/validate_apis.py`)
- [x] CISA SCuBA / ScubaGear compliance cross-walk for Microsoft 365 and Azure tenants (`docs/tasks/assurance/cisa-scuba-compliance.md`)
- [x] LOLBAS & GTFOBins binary telemetry coverage auditor (`tools/audit_lolbas_coverage.py`)
- [x] Active Directory Kerberos & LDAP protocol hardening baseline (`docs/tasks/hardening/ad-kerberos-ldap-hardening.md`)
- [x] Centralized event forwarding pipeline with WEF and Rsyslog TLS (`docs/tasks/administration/centralized-log-forwarding-wef-rsyslog.md`)

**Repository areas:** `tools/validate_mitre.py`, `tools/validate_apis.py`, `tools/audit_lolbas_coverage.py`, `site/mitre_attack_coverage.json`, `docs/references/mitre-attack-matrix.md`, `docs/tasks/assurance/`

</div>

<div class="cc-phase" markdown>

## Phase 8 — Practitioner Operational Experience (POX)

**Status:** ✅ Complete

**Objective:** enhance practitioner speed and execution safety through lightweight, dependency-free interactive web capabilities and companion terminal tooling — without compromising raw Markdown readability or offline autonomy.

**Key capabilities**

- [x] **Parameterized Command Builder** (`docs/assets/javascripts/cc-interactive.js` & `cc-interactive.css`): automated parameter detection (`<TARGET_IP>`, `<TARGET_HOST>`, `<UPN>`), live multi-block parameter synchronization, highlighted syntax interpolation, and one-click clipboard copying.
- [x] **Branching Diagnostic Decision Trees**: interactive visual troubleshooting widgets (Step 1 $\rightarrow$ Click [Exit 0] / [Timeout] $\rightarrow$ next diagnostic branch) with graceful fallback to collapsible Markdown.
- [x] **Terminal Companion CLI (`cc`)**: zero-dependency offline shell tool (`tools/cc_cli.py`, `cc.cmd`, `cc.ps1`, `cc.sh`) for instant search, syntax viewing, and verified script execution directly from PowerShell or Bash.

**Repository areas:** `docs/assets/javascripts/cc-interactive.js`, `docs/assets/stylesheets/cc-interactive.css`, `tools/cc_cli.py`, `cc.cmd`, `cc.ps1`, `tools/`

</div>

<div class="cc-phase" markdown>

## Phase 9 — Threat Hunting Operational Mastery

**Status:** ✅ Complete

**Objective:** develop systematic, hypothesis-driven proactive hunting playbooks that assume breach and isolate stealthy adversary behaviors before alert generation.

**Key capabilities**

- [x] Hypothesis-driven hunt playbooks mapped across enterprise kill chains (`docs/tasks/threat-hunting/hypothesis-driven-hunting-framework.md`)
- [x] Statistical baselining and frequency analysis queries (`docs/tasks/threat-hunting/statistical-baselining-frequency-analysis.md`)
- [x] Cross-platform behavioral hunting queries (`docs/tasks/threat-hunting/cross-platform-behavioral-hunting.md`)
- [x] Ephemeral asset and living-off-the-cloud anomaly detection (`docs/tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md`)
- [x] Automated hunt finding capture and retrospective validation engine (`tools/hunt_runner.py`)

**Repository areas:** `docs/tasks/threat-hunting/`, `tools/hunt_runner.py`, `docs/detection/`, `docs/platforms/`

</div>

<div class="cc-phase" markdown>

## Phase 10 — Cyber Threat Intelligence (CTI) & Threat-Informed Defense

**Status:** ✅ Complete

**Objective:** translate strategic and tactical adversary intelligence into actionable detection engineering, defense validation, and prioritized threat modeling.

**Key capabilities**

- [x] Structured Threat Information Expression (STIX 2.1) & TAXII 2.1 threat feed ingestion and normalization pipelines (`docs/tasks/threat-intelligence/stix-taxii-pipeline.md`)
- [x] Adversary emulation profiles and ATT&CK heatmaps for prevalent threat actors (`docs/tasks/threat-intelligence/adversary-emulation-profiling.md`)
- [x] Automated indicator of compromise (IoC) extraction, deduplication, and scoring workflows (`docs/tasks/threat-intelligence/ioc-lifecycle-scoring.md`)
- [x] Threat actor profile reference cards detailing tooling, infrastructure habits, and initial access vectors (`docs/references/threat-actor-profiles.md`)
- [x] Detection gap analysis engine aligning CTI reporting against deployed SIEM/EDR detection coverage (`tools/cti_gap_analyzer.py`)

**Repository areas:** `docs/tasks/threat-intelligence/`, `docs/references/threat-actor-profiles.md`, `tools/cti_gap_analyzer.py`, `docs/detection/`

</div>

<div class="cc-phase" markdown>

## Phase 11 — Quality & Verification

**Status:** 🟡 In progress

**Objective:** every script and tool the site publishes is linted and tested in CI, so "documented" also means "verified". Today 7 of 76 scripts have Pester tests, there is no PowerShell or shell linting in CI, and the 11 Python tools have no tests.

**Key capabilities**

- [x] PSScriptAnalyzer (repo settings) and ShellCheck jobs in `build.yml`, with existing findings fixed or explicitly baselined (`tests/lint/`)
- [x] Data-driven Pester contract suite that discovers every script in `scripts/powershell/`: comment-based help present, `TargetEnvironment` validated, `Test` mode runs without live calls (`tests/powershell/ScriptContract.Tests.ps1`)
- [ ] pytest suite for `tools/*.py` (validators, sanitizer, CLI, AI indexer/grounding) run in CI
- [ ] Coverage figures reported on the site instead of stated by hand

**Repository areas:** `tests/`, `.github/workflows/build.yml`, `scripts/`, `tools/`

</div>

<div class="cc-phase" markdown>

## Phase 12 — Local AI Assistant v2

**Status:** 🔵 Planned

**Objective:** turn the Phase 6 grounding engine into a day-to-day assistant: ask a question from the terminal, get an answer built only from Command & Code content, with every claim traceable to a page.

**Key capabilities**

- [ ] `cc ask "<question>"` in the terminal CLI, wrapping `tools/ai_grounding.py` (local Ollama, configurable model and host)
- [ ] Answers cite the source pages and code blocks they used; uncited answers are flagged
- [ ] Evaluation set of real practitioner questions with expected source pages, scored offline
- [ ] Index rebuild wired into the build so the assistant never answers from stale content

**Repository areas:** `tools/ai_grounding.py`, `tools/ai_indexer.py`, `tools/cc_cli.py`, `tests/`

</div>

<div class="cc-phase" markdown>

## Phase 13 — Website UX/UI Refactor

**Status:** 🔵 Planned

**Objective:** make the published site easy to use for a practitioner under pressure — find the right page in seconds on desktop or phone — while keeping Markdown sources readable and the build dependency-light.

**Key capabilities**

- [ ] UX/UI audit of the current site (navigation depth, landing pages, browse tables, search results, mobile layout, interactive widgets) with prioritized findings
- [ ] Information architecture and navigation redesign agreed with the owner before implementation
- [ ] Landing and index pages rebuilt around tasks ("I need to…") rather than file structure
- [ ] Theme, typography and component refresh in `overrides/` and `docs/assets/`, checked for accessibility and dark mode

**Repository areas:** `mkdocs.yml`, `overrides/`, `docs/assets/`, `docs/index.md`, section `index.md` pages

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
