# Command & Code — Project Standards & Golden Standards Bridge
> **Created**: 2026-10-06T02:44:00Z
> **Last Modified**: 2026-10-06T02:44:00Z
> **Author**: RJGProjectz
> **Scope**: Command & Code (`command-and-code`) Repository

---

## 1. Overview & Precedence

This document defines the project-local conventions and bridge to [`Standards/GOLDEN_STANDARDS.md`](file:///g:/AI-Playground/C&C/command-and-code/Standards/GOLDEN_STANDARDS.md) for the Command & Code repository.

Per **Golden Standards §0 (Precedence)**:
1. Explicit instructions from the human author (`RJGProjectz`).
2. This project-local standard (`PROJECT_STANDARDS.md`).
3. Global Golden Standards (`GOLDEN_STANDARDS.md`).
4. Vendor/platform best practice.

---

## 2. Information Architecture & Schema Alignment

Command & Code serves as a public/team-facing MkDocs documentation engine and field manual, while adhering to the core security engineering principles of Golden Standards.

| Dimension | Command & Code Implementation | Golden Standards Equivalent | Alignment Rule |
| --- | --- | --- | --- |
| **Front Matter Schema** | YAML schema validated by `tools/cc.py` and `tools/vocabulary.yml` (`platforms`, `languages`, `tasks`, `type`, `verified`) | Golden Schema (`id`, `category`, `platform`, `security_domain`, `status`, `technique`, `tactic`) | Front matter fields required by MkDocs navigation are maintained. Universal attributes (`Author: RJGProjectz`, ISO 8601 UTC timestamps) apply across all files. |
| **Security Domain** | Categorized under `tasks/` (Incident Response, Threat Hunting, Investigation, Troubleshooting, Administration, Detection Engineering, Hardening, Forensics, Automation) | 8 Mandatory Domains: Identity, Endpoint, Network, Cloud, Application, Operations, Governance, Intelligence | Every entry maps to a primary Golden Security Domain in its content and categorization. |
| **Script Taxonomy** | Operational scripts located in `scripts/<lang>/` | `FUNC_<PLATFORM>_<ACTION>_<OBJECT>.<ext>` | Scripts in `scripts/` provide copy-pasteable operational tools for field analysts. New automated tooling and test harnesses follow the `FUNC_*` prefix and include `.NOTES` headers. |
| **Audit & Governance** | Dual task ledgers (`TASK_LEDGER.md`, `task_ledger.ndjson`) and `Audit/Agent_Activity.md` | §9 Quality Gates & Audit Artifacts | Fully enforced in `Audit/` and repo root. |

---

## 3. Mandatory Safeguards

1. **Safe by Default (§1 P2, §4.6):** All destructive or state-changing commands and scripts default to `Test` environment and support `-WhatIf` / `--whatif`.
2. **No Secrets in Source (§1 P4, §4.5):** All tokens, keys, and credentials must be parameterized or loaded from secure environment/credential stores.
3. **Commit Protocol (§2.4):** AI agents must not commit or push to Git without explicit human verification and approval.
4. **Timestamps (§3.3):** All metadata timestamps must use ISO 8601 UTC with `Z` suffix.
