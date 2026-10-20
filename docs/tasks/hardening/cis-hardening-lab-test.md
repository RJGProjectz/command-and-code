---
title: CIS Hardening Lab Test (Before/After Diff and Run Checklist)
type: workflow
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Assurance]
category: Workflow
security_domain: Governance
author: RJGProjectz
date_created: 2026-10-20
last_updated: 2026-10-20
tags: [cis-benchmark, compliance, audit, lab, regression, ndjson]
aliases: [cis before after, cis report diff, compare cis reports, cis regression gate, cis lab checklist, hardening test plan, FUNC_PS_COMPARE_CIS_REPORT, cis drift diff]
difficulty: intermediate
verified: true
last_verified: 2026-10-20
---

# CIS Hardening Lab Test (Before/After Diff and Run Checklist)
> **Created**: 2026-10-20T02:30:00Z
> **Last Modified**: 2026-10-20T02:30:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Run this in a lab snapshot first. The audit, block-monitor and diff tools only read; the hardening you
> apply between the two audits (GPO, security template, Ansible role, script) is what changes the host.
> Keep a snapshot or rollback plan for every step that applies settings.

**Trigger:** a CIS baseline (or a change to one) is about to be rolled out, or a scheduled audit shows
drift.

**Goal:** prove what the hardening fixed, what it broke and what users will hit, before production.

The tools: [Windows 11 audit](windows-11-cis-audit-tool.md), [Windows Server audit](windows-server-cis-audit-tool.md),
[Linux audit](linux-cis-audit-tool.md), [CIS block monitor](cis-block-monitor.md) and
`scripts/powershell/FUNC_PS_COMPARE_CIS_REPORT.ps1` (the diff, below; runs in `pwsh` on Linux too).

## 1. Prepare the lab

| VM | Profile | Notes |
| :--- | :--- | :--- |
| Windows 11 Enterprise | L1, then L2 | Domain-joined if the GPOs are domain GPOs; local security template otherwise |
| Windows Server 2022/2025 member server | MS L1 | Needs a server catalog (build steps on the [Server page](windows-server-cis-audit-tool.md)) |
| Windows Server domain controller | DC L1 | Separate lab domain; never test DC settings on a production domain |
| Ubuntu 24.04 LTS | `ubuntu2404` L1 | auditd installed (CIS 6.2), AppArmor enabled |
| RHEL 9 / Rocky 9 / Alma 9 | `rhel9` L1 | SELinux enforcing; fapolicyd if you use it |

Checklist before the first run:

- [ ] Snapshot every VM ("pre-CIS").
- [ ] Copy the repo `scripts/` folder (or a release) to each VM; on Windows, unblock the files.
- [ ] Windows: a catalog for the host's OS and role in `scripts/cis/catalogs/`.
- [ ] Linux: add the execve EACCES audit rule from the [block monitor page](cis-block-monitor.md#linux) so
      `noexec` blocks are logged.
- [ ] Clock in sync (reports and events are compared by UTC time).
- [ ] An evidence folder per VM: `before/`, `after/`, `diff/`, `blocks/`.

## 2. Baseline audit (before)

```powershell
# Windows (elevated)
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath C:\cis-evidence\before
```

```bash
# Linux
sudo ./scripts/bash/audit_cis_linux.sh --level L1 --output-dir /var/tmp/cis-evidence/before
```

Keep the JSON report; the NDJSON and CSV work as diff input too.

## 3. Apply the hardening in audit mode first

Where a control has an audit mode, use it for the first pass: AppLocker and App Control in audit mode,
ASR rules in Audit, SELinux permissive for a new policy module, AppArmor complain mode. Then use the hosts
as users would (sign in, install the line-of-business apps, run the usual scripts) for at least one
working day.

```powershell
.\scripts\powershell\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -IncludeAudit -Hours 48 | Export-Csv C:\cis-evidence\blocks\audit-mode.csv -NoTypeInformation
```

```bash
sudo ./scripts/bash/FUNC_BASH_GET_CIS_BLOCK_EVENTS.sh --include-audit > /var/tmp/cis-evidence/blocks/audit-mode.ndjson
```

Every distinct `path` with `result` = `Audited` is either an allow-list entry to add or a block users will
hit on enforcement day.

## 4. Enforce, audit again (after), and diff

Switch the controls to enforce, reboot where the setting needs it, run the same audit command into
`after/`, then compare:

```powershell
.\scripts\powershell\FUNC_PS_COMPARE_CIS_REPORT.ps1 `
    -BaselinePath C:\cis-evidence\before\cis-PC01-L1-20261020T080000Z.json `
    -CurrentPath  C:\cis-evidence\after\cis-PC01-L1-20261020T160000Z.json `
    -OutputPath   C:\cis-evidence\diff |
    Format-Table cis_id, change, before, after, actual_after
```

```bash
pwsh ./scripts/powershell/FUNC_PS_COMPARE_CIS_REPORT.ps1 \
    -BaselinePath /var/tmp/cis-evidence/before/cis-web01-L1-20261020T080000Z.json \
    -CurrentPath /var/tmp/cis-evidence/after/cis-web01-L1-20261020T160000Z.json \
    -FailOn Regression -OutputPath /var/tmp/cis-evidence/diff
```

Input is detected from the content: `cc.cis.report/1` JSON, `cis.check` NDJSON (Linux stdout) or the audit
CSV. Each recommendation gets one change class:

| Change | Meaning | What to do |
| :--- | :--- | :--- |
| `Fixed` | Fail/Error → Pass | Expected result of the rollout |
| `Regressed` | Pass → Fail/Error | Something in the change undid a setting: find the GPO/role that wins |
| `StatusChanged` | e.g. NotApplicable → Pass, Fail → Error | Check `Error` first: the audit could not read the value (run elevated) |
| `ActualChanged` | Same status, new value | Partly applied (e.g. 60 → 30 when 15 is required) |
| `Added` / `Removed` | Only in one report | Different catalog, level or filter between the runs |
| `Unchanged` | Same status and value | Shown only with `-IncludeUnchanged` |

The summary (`cis.diff.summary` NDJSON event, and the `summary` object in `cis-diff-<time>.json`) carries
both scores (`pass / (pass + fail)`) and the count per class. A warning is logged when host, benchmark or
profile differ between the reports. `-FailOn Regression` exits 1 when anything regressed, for a change
pipeline or a scheduled drift job.

## 5. Read the blocks after enforcement

Run the block monitor without `-IncludeAudit` / `--include-audit` after the enforcement day. Triage as on
the [block monitor page](cis-block-monitor.md#read-the-results); a block of a needed application goes back to
step 3 as an allow-list change, then repeat step 4.

## 6. Record and roll back

- [ ] Keep `before/`, `after/`, `diff/` and `blocks/` with the change record.
- [ ] Every `Regressed` item has an owner and a fix or an accepted exception.
- [ ] Revert to the "pre-CIS" snapshot and replay the final settings once, to prove the rollout is
      repeatable from scratch.
- [ ] Schedule the audit with `--fail-on` / `-FailOn` and diff each run against the accepted report for
      drift.

## Tests and CI

| Suite | Covers | CI job |
| :--- | :--- | :--- |
| `tests/powershell/CisAudit.Tests.ps1` | Windows audit engine on a fake host context | `pester` (Linux, pwsh 7) and `cis-windows` (Windows PowerShell 5.1) |
| `tests/powershell/CisBlockEvents.Tests.ps1` | Windows block monitor on synthetic exported events | same |
| `tests/powershell/CisReportDiff.Tests.ps1` | Diff classes, JSON/NDJSON/CSV input, summary, files, exit code | same |
| `tests/python/test_audit_cis_linux.py` | Linux audit on synthetic Ubuntu and Rocky file trees | `pytest` (Ubuntu runner) |
| `tests/python/test_cis_block_events_linux.py` | Linux block monitor on synthetic `audit.log` and syslog | `pytest` |

The `cis-windows` job runs the Windows suites under Windows PowerShell 5.1 on a Windows runner, because the
scripts must work on the in-box shell of the hosts they audit. The fixtures are synthetic: they prove the
parsing and the logic, not that a live host writes the same field names. That is what this lab run is for.

## Limits

- The diff compares by recommendation ID. Two reports from different benchmark versions can carry the
  same ID for different settings; the diff warns when the benchmark name differs, not when only the
  version does.
- Doc-checked; the lab procedure has not yet been run end to end on live VMs.

## Related

- [Windows security baseline](windows-security-baseline.md), [Linux security baseline](linux-security-baseline.md)
- [AppLocker phased rollout](applocker-deployment-rollout.md)
- [Windows CIS ASR & Credential Guard](windows-cis-attack-surface-reduction.md)
