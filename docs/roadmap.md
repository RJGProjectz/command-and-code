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
FOUNDATION            🟡  ← you are here
    ↓
KNOWLEDGE EXPANSION   🔵
    ↓
AUTOMATION & TOOLING  🔵
    ↓
API INTEGRATION       🔵
    ↓
OPERATIONAL PLAYBOOKS 🔵
    ↓
LOCAL AI              ⚪
    ↓
SECURITY TOOLKIT      ⚪
```

</div>

**Status key:** ✅ Complete · 🟡 In progress · 🔵 Planned · ⚪ Future

<div class="cc-phase cc-active" markdown>

## Phase 1 — Foundation

**Status:** 🟡 In progress (V1)

**Objective:** a highly organised, searchable knowledge base with consistent metadata and CI.

**Key capabilities**

- [x] Repository structure, MkDocs + Material site, GitHub Actions build and Pages deploy
- [x] Platform / Language / Task navigation with generated browse tables
- [x] Search tuned with aliases and boosts
- [x] Metadata conventions and validation (`tools/cc.py`)
- [x] Windows, Linux, Microsoft 365 and virtualization reference entries
- [x] PowerShell, Bash and Python language pages
- [x] KQL, SPL, S1QL and Sigma detection content; ATT&CK mapping
- [x] Incident-response, investigation, hunting and troubleshooting workflows
- [x] Initial toolbox scripts with documentation
- [ ] Verify S1QL and environment-specific SPL content in production consoles
- [ ] Publish to GitHub Pages

**Repository areas:** `docs/`, `scripts/`, `templates/`, `tools/`, `.github/workflows/`

</div>

<div class="cc-phase" markdown>

## Phase 2 — Knowledge Expansion

**Status:** 🔵 Planned

**Objective:** move from *"what command do I use?"* to *"what am I trying to accomplish, what telemetry do I need, what query should I run, and what do I do with the result?"*

**Key capabilities:** broader command and query coverage · more configuration references · troubleshooting decision trees · expanded IR and hunting workflows · deeper ATT&CK relationships · more cross-platform equivalents · environment/version notes.

**Repository areas:** `docs/platforms/`, `docs/detection/`, `docs/tasks/`, `docs/references/`

</div>

<div class="cc-phase" markdown>

## Phase 3 — Automation & Tooling Integration

**Status:** 🔵 Planned

**Objective:** progressively import existing PowerShell, Bash and Python automation as documented, connected tools — not a dump of files.

**Key capabilities:** every significant tool documents purpose, problem, requirements, inputs, outputs, dependencies, usage, security considerations, example, and related commands/APIs/workflows, and links to its source.

**Repository areas:** `scripts/`, `docs/toolbox/`

</div>

<div class="cc-phase" markdown>

## Phase 4 — API & Platform Integration

**Status:** 🔵 Planned

**Objective:** practical, tested examples for security APIs, organised by the same Platform / Technology / Task model.

**Key capabilities:** Microsoft Graph, Defender, Entra, Intune and Sentinel APIs · Splunk and SentinelOne APIs · authentication patterns · JSON processing · reporting.

```text
Microsoft Defender → Microsoft Graph → API → PowerShell / Python → Automation → Workflow
```

**Repository areas:** `docs/languages/*/rest-apis`, new `docs/apis/` section, `scripts/`

</div>

<div class="cc-phase" markdown>

## Phase 5 — Operational Playbooks

**Status:** 🔵 Planned

**Objective:** end-to-end playbooks (alert → scope → contain → remediate → document) that link to entries rather than duplicating commands.

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
