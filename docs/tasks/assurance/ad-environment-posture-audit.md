---
title: AD Environment Posture Audit - STIG / CIS / Best-Practice Crosswalk
type: tool
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-26
difficulty: intermediate
tags:
  - active-directory
  - stig
  - cis-benchmark
  - posture
  - compliance
  - kerberos
  - delegation
  - laps
  - ndjson
aliases: [ad posture audit, active directory posture, Invoke-AdPostureAudit, domain posture, ad stig cis crosswalk, krbtgt age check, kerberoasting audit]
---

# AD Environment Posture Audit - STIG / CIS / Best-Practice Crosswalk

`scripts/powershell/Invoke-AdPostureAudit.ps1` grades the whole Active Directory **domain** against a
posture catalog (`scripts/cis/catalogs/adposture/ad-posture-v1.json`) in which **every check carries up
to three framework expectations** and is validated against each one that applies:

- **STIG** - DISA Windows Server / Active Directory Domain STIG.
- **CIS** - the **Domain Controller profile** of the CIS Microsoft Windows Server Benchmark. There is
  no standalone "CIS Active Directory" benchmark, so AD-only checks (delegation, Kerberoasting SPNs,
  LAPS coverage, trusts, recycle bin) omit CIS and are marked `n/a`.
- **Best practice** - documented Microsoft / community hardening guidance. **Best practice is the
  minimum pass bar.**

It is **read-only**: it reads the domain through the RSAT `ActiveDirectory` module and `secedit`; no
directory object is changed. Run it monthly, and after any change to privileged groups.

!!! warning "STIG rule identifiers are representative"
    Rule IDs in the catalog (e.g. `WN-AC-000035`, `AD.0017`) are representative and change between STIG
    releases. Confirm the exact rule IDs against the STIG version your organisation is assessed against.

## The pass bar

Every check records a per-framework verdict (`Stig` / `Cis` / `BestPractice`) **and** an overall
`Status`, decided by `-Bar`:

| `-Bar` | Overall `Status` passes when ... | Use when |
| --- | --- | --- |
| `BestPractice` (default) | the **best-practice** expectation is met (the minimum bar) | a pragmatic baseline; still shows where STIG/CIS are stricter |
| `Strictest` | **every** framework on the check is met | accreditation against the strictest applicable standard |

A worked example - maximum password age set to 90 days: STIG and best practice want 60 or fewer
(**Fail**), CIS allows 365 or fewer (**Pass**). At the default `BestPractice` bar the overall status is
**Fail**, and the row still shows `cis=Pass` so you can see exactly which frameworks diverge.

## Easy run

```powershell
# Default: best-practice bar, report written next to the script
.\Invoke-AdPostureAudit.ps1
```

```powershell
# Accreditation view: a check passes only if STIG, CIS and best practice all pass
.\Invoke-AdPostureAudit.ps1 -Bar Strictest -OutputPath D:\Evidence
```

```powershell
# Target a specific DC and tighten the stale-account window to 60 days
.\Invoke-AdPostureAudit.ps1 -Server dc01.contoso.com -StaleDays 60 | Where-Object Status -ne 'Pass'
```

Writes `adposture-<HOST>-<UTC>.json` (schema `cc.adposture.report/1`), `.ndjson` and `.csv`. Merges
into the one-command [Posture Audit](posture-audit.md) on a domain controller.

## What it checks

| Area | Checks | Frameworks |
| --- | --- | --- |
| Password policy | length, history, max/min age, complexity, reversible encryption | STIG + CIS + BP |
| Account lockout | threshold, duration, reset counter | STIG + CIS + BP |
| Kerberos | `krbtgt` password age, user accounts with SPNs (Kerberoasting) | STIG / BP |
| Privileged access | Schema / Enterprise / Domain Admins membership, Protected Users, LAPS coverage | STIG / BP |
| Delegation | non-DC accounts trusted for unconstrained delegation | STIG + BP |
| Domain config | machine account quota, functional level, AD Recycle Bin, tombstone lifetime | BP |
| Account hygiene | stale enabled users/computers, password-never-expires | STIG / BP |
| Built-in accounts | Guest disabled, Administrator renamed | STIG + CIS + BP |
| Trusts | SID filtering (quarantine) on external/forest trusts | STIG + BP |

A check whose fact cannot be collected (missing permission, feature or module) reports `Error`, not a
false `Pass`.

## Operator guide

1. Run from a domain-joined host (a DC, or a management workstation) with the RSAT **ActiveDirectory**
   module installed (`Install-WindowsFeature RSAT-AD-PowerShell`, or
   `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`).
2. A standard domain user can read most facts; a few (e.g. recursive privileged-group expansion) are
   more complete with Domain Admin read. The script never writes.
3. Copy `scripts/powershell/AdPosture/`, `scripts/powershell/CisAudit/` (shared expectation evaluator),
   `scripts/powershell/Invoke-AdPostureAudit.ps1` and `scripts/cis/catalogs/adposture/` to the target,
   keeping the relative layout.

## Extending the catalog

Add a check to `ad-posture-v1.json` with a `collector` key, a `category`, and a `frameworks` object of
`stig` / `cis` / `bestPractice` (each `{ id?, source?, expect }`, where `expect` uses the shared
operators `eq`, `ne`, `range`, `in`, `regex`, `set`, ...). Add the matching fact to
`Get-AdPostureContext` in `AdPosture.psm1`. Best practice should always be present so the default bar
can grade the check.

## See also

- [Posture Audit](posture-audit.md) - the one-command umbrella that runs this on a domain controller.
- [Assurance Check - Active Directory STIG Compliance](ad-stig-compliance.md) - the earlier DC STIG snippet this engine generalises.
- [Hardening - Active Directory Kerberos & LDAP Protocol Hardening](../hardening/ad-kerberos-ldap-hardening.md) - remediation for the delegation / Kerberos findings.
