# Project Instructions — AI Agent Operating Rules
> **Created**: 2026-10-06T02:47:00Z
> **Last Modified**: 2026-10-06T02:47:00Z
> **Author**: RJGProjectz

- The authoritative rule set is [`Standards/GOLDEN_STANDARDS.md`](../Standards/GOLDEN_STANDARDS.md) and [`Standards/PROJECT_STANDARDS.md`](../Standards/PROJECT_STANDARDS.md). Read §1, §2 and §11 before any change; follow the section for the asset type you are producing.
- Treat this repo as a governed security automation and knowledge base project. Stay in repo scope; no global/system-wide changes.
- Default to `Test` + dry-run/`-WhatIf`; live action only when explicitly requested.
- Scaffold from `templates/`; naming `FUNC_<PLATFORM>_<ACTION>_<OBJECT>`; approved Verb-Noun functions.
- No implicit automatic variables (`$Matches`, `$Args`, `$Input`, `$Event`, `$Host`, `$Error`, `$LastExitCode`) as working data.
- `Set-StrictMode -Version 3.0`; `$ErrorActionPreference = 'Stop'`.
- Mandatory metadata: `security_domain`, `Author: RJGProjectz`, ISO 8601 UTC (`Z`) timestamps.
- Never commit secrets; never commit/push to Git without presenting a diff and getting human approval (§2.4).
- Keep dual ledgers (`TASK_LEDGER.md` + `task_ledger.ndjson`) and `Audit/Agent_Activity.md` updated after each cycle.
