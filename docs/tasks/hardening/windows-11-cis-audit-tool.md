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

!!! note "Catalog included"
    The repository ships the Windows 11 Enterprise v5.1.0 catalog
    (`scripts/cis/catalogs/windows11-enterprise-v5.1.0.json`, 486 checks). It holds only recommendation
    IDs, titles and the settings checked, derived from Tenable's CIS audit files; no CIS rationale or
    remediation text. To build a catalog for another benchmark version, see [Get a catalog](#get-a-catalog).

!!! warning "Before you run anything"
    Run it from an **elevated** PowerShell (5.1 or 7). Without administrator rights, `secedit /export` and
    `auditpol` are denied, so account policy, user rights and audit policy checks report **Error**
    (80 of 486 checks); the rest still run. The tool was run on Windows 11 (build 26200) in PowerShell 5.1
    and 7.6 on 2026-10-16, unelevated, with identical results in both versions.

## Get a catalog

1. Download the audit files for your benchmark from [tenable.com/audits](https://www.tenable.com/audits)
   under your own Tenable / CIS terms, e.g. `CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1.audit` and
   `..._L2.audit`. Check each file's SHA256 against the value on its audit page.
2. Build the catalog into the catalog folder:

```powershell
python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows 11 Enterprise" --version 5.1.0 `
    --out scripts/cis/catalogs/windows11-enterprise-v5.1.0.json .\CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L1.audit .\CIS_Microsoft_Windows_11_Enterprise_v5.1.0_L2.audit
```

3. Keep the downloaded audit files out of version control (`.gitignore` excludes `*.audit`); commit
   the generated catalog.

The level of each check comes from the file name (`_L1` / `_L2`). Re-run the same command when a new
benchmark version is released (and pass the new file to `-CatalogPath`). For v5.1.0 the result has 486
checks (371 L1, 115 L2).

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
| `-FailOn` | Exit code for automation: `None` (default, 0), `Fail` (1 on any Fail), `FailOrError` (also 2 when the audit was incomplete) |

```powershell
# Scheduled compliance gate: evidence files plus an exit code the scheduler can alert on
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath D:\Evidence -Quiet -FailOn FailOrError
```

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

- **JSON** — one report: benchmark, profile, host, execution ID, summary and all results, plus the
  evidence needed to trust it later: catalog file name and **sha256**, OS edition and build,
  PowerShell edition/version, elevation, and which audit-policy source was used.
- **NDJSON** — one line per recommendation with the SIEM fields from GOLDEN_STANDARDS §4.7
  (`timestamp`, `host`, `tool`, `version`, `execution_id`, `level`, `action` = `cis.check`, `target`,
  `result`) plus `cis_id`, `title`, `expected`, `actual`, `source`, `catalog_sha256`, `os_edition`,
  `os_build` and `elevated`. `level` is `WARN` for Fail and
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
  `secedit` user right (accounts resolved from SIDs; exact set or "includes"), audit policy
  subcategory (matched by GUID, see below), and service state (only to pick the right variant of 2.2.22 / 2.2.23 when the Print
  Spooler runs). Recommendations that need several settings (e.g. 18.5.1 AutoAdminLogon) pass only
  when all of them pass.
- **Source of the check logic** — the catalog is generated from the Tenable audit files for the
  benchmark (sha256 of each source file recorded in the catalog; the catalog's own sha256 is
  recorded in every report). Only recommendation IDs, titles and the settings checked are stored; CIS
  rationale and remediation text is not reproduced. Use your CIS WorkBench copy for that.

## Limits

- Manual recommendations in the benchmark (not automatable) are not in the catalog.
- **Display language**: audit policy is read with `auditpol /backup`, whose numeric *Setting Value*
  (1 = Success, 2 = Failure, 3 = both; MS-GPAC) and subcategory **GUIDs** do not depend on the Windows
  language. If the backup cannot be written, the tool falls back to `auditpol /get /r`, still matched
  by GUID, but that output's setting text is localized. The `/backup` path follows the documented
  audit.csv format and the unit tests; it has not yet been run elevated on a non-English host.
- **Edition**: the benchmark targets Enterprise/Education. On Home (`Core`) and Pro the tool warns,
  because many Section 18 policies are ignored there: a registry value can pass without being
  enforced.
- Domain-joined hosts: the result is the **effective** local policy. Fix failures in the GPO, not on the
  host, or the next policy refresh reverts them.
- The tool reports; it does not remediate. Use the hardening guides below to change settings.

## Tests

- CI never uses licensed data. `tests/powershell/fixtures/cis/Synthetic_v1.0.0_L1.audit` is a small
  hand-written audit file in the same format; `catalog-synthetic.json` is built from it.
- `tests/powershell/CisAudit.Tests.ps1` (Pester 5, runs in CI on Linux): catalog contract (unique IDs,
  titles, only supported test types, no rationale fields, audit GUID coverage) on the synthetic catalog
  **and on every catalog in `scripts/cis/catalogs/`**, plus fixture tests for every test source, variants,
  user hives and unreadable sources. Run it after building a new catalog.
- `tests/python/test_build_cis_catalog.py`: generator on the synthetic audit file, and a check that
  the committed synthetic catalog matches the generator output.

## Related

- [Windows Server CIS audit (Member Server / Domain Controller)](windows-server-cis-audit-tool.md)
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
- [auditpol backup](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-backup)
- [MS-GPAC: Subcategory and SubcategoryGUID](https://learn.microsoft.com/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d)
- [MS-GPAC: Example involving system audit subcategory settings](https://learn.microsoft.com/openspecs/windows_protocols/ms-gpac/f2b42f67-98d0-4900-8b66-e9e7db31698a)
