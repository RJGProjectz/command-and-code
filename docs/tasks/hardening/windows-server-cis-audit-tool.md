---
title: Windows Server CIS Benchmark Audit (Member Server / Domain Controller)
type: tool
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
  - Python
tasks:
  - Hardening
  - Assurance
  - Administration
verified: true
last_verified: 2026-10-19
difficulty: intermediate
tags:
  - cis-benchmark
  - compliance
  - audit
  - domain-controller
  - member-server
  - ndjson
aliases: [cis audit windows server, cis windows server 2022 audit, cis windows server 2025 audit, cis member server audit, cis domain controller audit, cis ms profile, cis dc profile, server hardening audit script, Invoke-CisWindowsAudit server]
---

# Windows Server CIS Benchmark Audit (Member Server / Domain Controller)

The [Windows 11 CIS audit tool](windows-11-cis-audit-tool.md) also audits **Windows Server** against the
CIS Microsoft Windows Server Benchmarks (2022, 2025 and other releases Tenable publishes audit files for).
Same engine, same runner (`scripts/powershell/Invoke-CisWindowsAudit.ps1`), same Pass / Fail /
NotApplicable / Error results and JSON / NDJSON / CSV reports. What changes is the **catalog**: a server
benchmark has two profiles, and you build one catalog per profile.

| CIS profile | Applies to | Catalog file name (convention) |
| :--- | :--- | :--- |
| Level 1 / Level 2 - **Member Server** (MS) | Domain members and standalone (workgroup) servers | `windows-server-<release>-ms-v<version>.json` |
| Level 1 / Level 2 - **Domain Controller** (DC) | Domain controllers | `windows-server-<release>-dc-v<version>.json` |

!!! warning "No server catalog ships with the repository"
    Server catalogs are built by you from the audit files you download under your own Tenable / CIS terms.
    The tool never guesses: with no matching catalog it stops and prints the build command. Read-only in
    `Test` and `Prod`; run it **elevated** on the server, or account policy, user rights and audit
    policy checks report `Error`.

## Build the catalogs

1. On [tenable.com/audits](https://www.tenable.com/audits), find your release, e.g. *CIS Microsoft
   Windows Server 2025 v2.1.0*, and download the four files you need. Current names end in the level and
   the profile:

    ```text
    CIS_Microsoft_Windows_Server_2025_v2.1.0_L1_MS.audit
    CIS_Microsoft_Windows_Server_2025_v2.1.0_L2_MS.audit
    CIS_Microsoft_Windows_Server_2025_v2.1.0_L1_DC.audit
    CIS_Microsoft_Windows_Server_2025_v2.1.0_L2_DC.audit
    ```

    Older releases use `_L1_Member_Server` / `_L1_Domain_Controller`; the builder reads both. Check each
    file's SHA256 against its audit page. Pages marked *deprecated* are older benchmark versions: take
    the newest one.

2. Build **one catalog per profile** (the builder refuses to mix MS and DC files: each profile has its
   own recommendation set and its own platform guard):

    ```powershell
    python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows Server 2025" --version 2.1.0 `
        --out scripts/cis/catalogs/windows-server-2025-ms-v2.1.0.json `
        .\CIS_Microsoft_Windows_Server_2025_v2.1.0_L1_MS.audit .\CIS_Microsoft_Windows_Server_2025_v2.1.0_L2_MS.audit

    python tools/build_cis_catalog.py --benchmark "CIS Microsoft Windows Server 2025" --version 2.1.0 `
        --out scripts/cis/catalogs/windows-server-2025-dc-v2.1.0.json `
        .\CIS_Microsoft_Windows_Server_2025_v2.1.0_L1_DC.audit .\CIS_Microsoft_Windows_Server_2025_v2.1.0_L2_DC.audit
    ```

    The output line shows the check count per level and the profile (`profile MS` / `profile DC`). The
    catalog records `"profile": "MS"` or `"DC"` and, per source file, its level, profile and sha256.

3. Keep the `.audit` files out of version control (`.gitignore` excludes `*.audit`). Run the Pester
   suite after building: its catalog contract test checks every catalog in `scripts/cis/catalogs/`.

The *Next Generation Windows Security* (NG) profile files are not supported by the builder yet.

## Run it

```powershell
# On a member server: the runner picks the newest windows-server-*-ms-*.json by itself
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath D:\Evidence\CIS

# On a domain controller, explicit catalog, Level 2, only what is not passing
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -CatalogPath .\scripts\cis\catalogs\windows-server-2025-dc-v2.1.0.json `
    -Level L2 | Where-Object Status -ne 'Pass'

# Scheduled gate on every server: exit 1 on drift, 2 when the audit was incomplete
.\scripts\powershell\Invoke-CisWindowsAudit.ps1 -Level L1 -OutputPath \\evidence\cis$ -Quiet -FailOn FailOrError
```

How the runner chooses and guards the catalog:

1. **Host role** from `Win32_OperatingSystem.ProductType`: `1` work station, `2` domain controller,
   `3` server. A standalone server counts as a member server, which is the profile CIS applies to it.
2. **Default catalog** when `-CatalogPath` is omitted: work station -> `windows11-enterprise-v5.1.0.json`,
   member server -> the last `windows-server-*-ms-*.json` by name, domain controller -> the last
   `windows-server-*-dc-*.json`. Keep one release per profile in the folder, or pass `-CatalogPath`.
3. **Role check**: an MS catalog on a DC (or the reverse, or a client catalog on a server) stops the run.
   The OS build and installation type guard from the audit file is checked as well. `-SkipApplicabilityCheck`
   audits anyway and marks the results as indicative.

Reports carry two extra fields for servers: `hostRole` (`MemberServer`, `DomainController`) and
`benchmarkProfile` (`MS`, `DC`) in the JSON report, `host_role` and `benchmark_profile` in every NDJSON line,
so a SIEM can split drift by role. The edition warning is client-only: Standard, Datacenter and Azure
Edition servers apply the full Group Policy set.

## Server-specific reading of the results

- **Account policies (section 1) on a domain controller** show the domain password and lockout policy
  (the Default Domain Policy). Fine-grained password policies override it for the users and groups they
  apply to and are **not** covered: review them with `Get-ADFineGrainedPasswordPolicy -Filter *` and
  `Get-ADUserResultantPasswordPolicy`.
- **Account policies on a member server** apply to its local SAM accounts only; domain accounts follow
  the domain policy.
- **DC-only and MS-only recommendations** have their own IDs in the benchmark (for example the two
  variants of *Access this computer from the network*), so each profile's catalog holds only its own.
- **Fix in the GPO, not on the server.** On DCs the result is the effective policy from the Default Domain
  Controllers Policy and any GPO linked to the Domain Controllers OU; a local change is reverted at the
  next refresh. See [Windows security baseline](windows-security-baseline.md) and
  [AD Kerberos and LDAP hardening](ad-kerberos-ldap-hardening.md).
- **Server Core**: the audit has no GUI dependency. Run it in PowerShell on the console or over
  PowerShell remoting (`Invoke-Command -FilePath`); copy the catalog next to the script on the target.

## Limits

- Not run on a live Windows Server yet: the server path follows the Tenable file naming, the
  documented `ProductType` values and the existing engine, and is covered by the unit tests below. Expect
  to confirm the check counts on the first real build.
- Manual recommendations are not in the catalog; the NG profile is not supported.
- Fine-grained password policies, AD object permissions and DNS / DHCP role settings are outside the
  benchmark checks the engine evaluates.

## Tests

- `tests/python/test_build_cis_catalog.py`: level and profile from every file-name form
  (`_L1_MS`, `_L2_DC`, `_L2_Member_Server`, `_L1_Domain_Controller`, client `_L1`), profile recorded in the
  catalog and each source, mixed MS + DC input rejected with exit code 2.
- `tests/powershell/CisAudit.Tests.ps1` (Pester 5, CI): `ConvertTo-CisHostRole` for every ProductType,
  `Test-CisCatalogRole` for every profile/role pair, server editions supported, and the catalog contract
  (profile is `MS` or `DC` and the same in every source) on every catalog in `scripts/cis/catalogs/`.

## Related

- [Windows 11 CIS audit tool](windows-11-cis-audit-tool.md) — catalog format, statuses, report files
- [Windows CIS user rights & account policies](windows-cis-user-rights-assignment.md)
- [Windows CIS advanced audit policy](windows-cis-advanced-audit-policy.md)
- [AD Kerberos and LDAP hardening](ad-kerberos-ldap-hardening.md)

## Sources

- [CIS Microsoft Windows Server Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [Tenable audit: CIS Microsoft Windows Server 2025 v2.1.0 L2 DC](https://www.tenable.com/audits/CIS_Microsoft_Windows_Server_2025_v2.1.0_L2_DC)
- [Tenable audit: CIS Microsoft Windows Server 2022 v5.1.0 L2 MS](https://www.tenable.com/audits/CIS_Microsoft_Windows_Server_2022_v5.1.0_L2_MS)
- [Tenable audit (older naming): CIS Microsoft Windows Server 2022 v3.0.0 L2 Member Server](https://www.tenable.com/audits/CIS_Microsoft_Windows_Server_2022_v3.0.0_L2_Member_Server)
- [Win32_OperatingSystem class (ProductType)](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem)
- [Get-ADFineGrainedPasswordPolicy](https://learn.microsoft.com/powershell/module/activedirectory/get-adfinegrainedpasswordpolicy)
- [Get-ADUserResultantPasswordPolicy](https://learn.microsoft.com/powershell/module/activedirectory/get-aduserresultantpasswordpolicy)
- [secedit /export](https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-export)
