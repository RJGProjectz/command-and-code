---
title: Windows 11 CIS Benchmark Audit Tool (L1 / L2)
type: tool
platforms:
  - Windows
languages:
  - PowerShell
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-16
difficulty: intermediate
tags:
  - cis-benchmark
  - compliance
  - audit
  - secedit
  - auditpol
  - ndjson
aliases: [cis audit windows 11, cis benchmark script, cis level 1 check, cis level 2 check, Invoke-CisWindowsAudit, cis compliance report, windows hardening audit]
---

# Windows 11 CIS Benchmark Audit Tool (L1 / L2)

`scripts/powershell/Invoke-CisWindowsAudit.ps1` checks a Windows 11 host against the **CIS Microsoft
Windows 11 Enterprise Benchmark v5.1.0**: 371 Level 1 and 115 Level 2 recommendations. It returns one
result per recommendation (CIS ID, title, expected, actual, Pass / Fail / NotApplicable / Error) and
can write JSON, NDJSON and CSV reports. It is **read-only**: nothing on the host is changed in either
`-TargetEnvironment Test` or `Prod`.

!!! warning "Before you run anything"
    Run it from an **elevated** PowerShell (5.1 or 7). Without administrator rights, `secedit /export` and
    `auditpol` are denied, so account policy, user rights and audit policy checks report **Error**
    (80 of 486 checks); the rest still run. The tool was run on Windows 11 (build 26200) in PowerShell 5.1
    and 7.6 on 2026-10-16, unelevated, with identical results in both versions.

## Run it

```powershell
# Level 1, console summary, reports to a folder
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath C:\Reports\CIS

# Level 2 (includes every L1 recommendation), audit policy section only, show what is not passing
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L2 -Section 17 | Where-Object Status -ne 'Pass'

# Selected recommendations, CSV only, no console output
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Id '2.3.*','18.9.*' -Format Csv -OutputPath .\out -Quiet
```

| Parameter | Use |
| :--- | :--- |
| `-Level L1` / `L2` | CIS profile; L2 includes L1 |
| `-Id` | Recommendation filter, wildcards (`'18.10.43.*'`) |
| `-Section` | Top-level sections: 1 Account Policies, 2 Local Policies, 5 System Services, 9 Firewall, 17 Advanced Audit Policy, 18 Admin Templates (Computer), 19 Admin Templates (User) |
| `-OutputPath`, `-Format` | Folder and formats (`Json`, `Ndjson`, `Csv`; default all three) |
| `-SkipApplicabilityCheck` | Audit a host that is not Windows 11 client (results indicative only) |
| `-CatalogPath` | Another catalog, e.g. a newer benchmark version |

## Read the results

| Status | Meaning |
| :--- | :--- |
| `Pass` | The setting matches the recommendation |
| `Fail` | Different value, or not configured where CIS requires a value |
| `NotApplicable` | Nothing to check (e.g. a per-user setting with no user hive loaded) |
| `Error` | The source could not be read (usually: not elevated) — not counted as a failure |

The score is `pass / (pass + fail)`; errors and not-applicable checks are excluded. "Not configured"
is a common `Fail` on stand-alone machines: many Section 18 recommendations require the policy value to
exist even when the Windows default behaves the same way.

Report files are named `cis-<host>-<level>-<UTC time>.<ext>`:

- **JSON** — one report: benchmark, profile, host, execution ID, summary and all results.
- **NDJSON** — one line per recommendation with the SIEM fields from GOLDEN_STANDARDS §4.7
  (`timestamp`, `host`, `tool`, `version`, `execution_id`, `level`, `action` = `cis.check`, `target`,
  `result`) plus `cis_id`, `title`, `expected`, `actual`, `source`. `level` is `WARN` for Fail and
  `ERROR` for Error, so a SIEM can alert on drift.
- **CSV** — `Id, Title, Level, Section, Status, Expected, Actual, Source, Detail` for spreadsheets and
  before/after comparison.

```powershell
# Compare two runs (before / after hardening)
$before = Import-Csv .\before.csv; $after = Import-Csv .\after.csv
Compare-Object $before $after -Property Id, Status | Sort-Object Id
```

## How it works

```text
tools/build_cis_catalog.py  ->  scripts/cis/catalogs/windows11-enterprise-v5.1.0.json  (data)
scripts/powershell/CisAudit/CisAudit.psm1                                              (engine)
scripts/powershell/Invoke-CisWindowsAudit.ps1                                          (runner)
```

- **Catalog** — one entry per recommendation: ID, title, level and the tests that decide it. Test
  sources: registry value (HKLM, or every loaded user hive for HKU), `secedit` System Access value,
  `secedit` user right (accounts resolved from SIDs; exact set or "includes"), `auditpol`
  subcategory, and service state (only to pick the right variant of 2.2.22 / 2.2.23 when the Print
  Spooler runs). Recommendations that need several settings (e.g. 18.5.1 AutoAdminLogon) pass only
  when all of them pass.
- **Source of the check logic** — the catalog is generated from Tenable's public CIS audit files for
  this benchmark (`CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1/L2.audit`, sha256 recorded in the
  catalog). Only recommendation IDs, titles and the settings checked are stored. CIS rationale and
  remediation text is licensed and is **not** reproduced; use your CIS WorkBench copy for that.
- **New benchmark release** — download the new audit files from tenable.com/audits, then:

```powershell
python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows 11 Enterprise" --version 5.2.0 `
    --out scripts/cis/catalogs/windows11-enterprise-v5.2.0.json .\L1.audit .\L2.audit
```

The audit files are not committed to the repository.

## Limits

- Manual recommendations in the benchmark (not automatable) are not in the catalog.
- `auditpol` subcategory names are English; on other display languages audit-policy checks report
  Error until a matching catalog exists.
- Domain-joined hosts: the result is the **effective** local policy. Fix failures in the GPO, not on the
  host, or the next policy refresh reverts them.
- The tool reports; it does not remediate. Use the hardening guides below to change settings.

## Tests

- `tests/powershell/CisAudit.Tests.ps1` (Pester 5, runs in CI on Linux): catalog contract (unique IDs,
  CIS titles, only supported test types, no rationale fields) and fixture tests for every test source,
  variants, user hives and unreadable sources.
- `tests/python/test_build_cis_catalog.py`: generator on a synthetic audit file.

## Related

- [Windows CIS user rights & account policies](windows-cis-user-rights-assignment.md)
- [Windows CIS advanced audit policy](windows-cis-advanced-audit-policy.md)
- [Windows CIS ASR & Credential Guard](windows-cis-attack-surface-reduction.md)
- [Windows audit policy](../../platforms/windows/audit-policy.md)

## Sources

- [CIS Microsoft Windows Desktop Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Tenable audit: CIS Microsoft Windows 11 Enterprise v5.1.0 L1](https://www.tenable.com/audits/CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1)
- [Tenable audit: CIS Microsoft Windows 11 Enterprise v5.1.0 L2](https://www.tenable.com/audits/CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L2)
- [secedit /export](https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-export)
- [auditpol get](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-get)
