---
title: Azure / Entra ID Identity Posture Audit
type: workflow
platforms:
  - Azure
  - Entra ID
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
  - Administration
verified: false
difficulty: intermediate
tags:
  - azure
  - entra-id
  - posture
  - cis-benchmark
  - mcsb
  - conditional-access
  - mfa
  - pim
  - compliance
aliases:
  - azure posture audit
  - Invoke-AzurePostureAudit
  - Azure identity posture
  - CIS Azure Foundations
  - Entra posture
  - Entra ID posture
---

# Azure / Entra ID Identity Posture Audit

`scripts/powershell/Invoke-AzurePostureAudit.ps1` is a **read-only** Azure identity posture audit
that grades the Entra ID tenant against a catalog of checks derived from the
[CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure) v3.0 and the
[Microsoft Cloud Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/) (MCSB)
v1.0.

!!! warning "VERIFY BEFORE PRODUCTION USE"
    This page is **verified: false** — the script and catalog were doc-checked against Microsoft
    Learn and the CIS benchmark documentation but have **not been run against a live Azure tenant**.
    Run in a non-production or read-only context first. CIS benchmark IDs in the catalog are
    indicative; confirm them against the version enforced in your Defender for Cloud
    regulatory-compliance view.

## What it checks — Phase 1 (Identity and Access Management)

| Check | Category | CIS | MCSB |
| :--- | :--- | :--- | :--- |
| AZ-ID-01: Security Defaults enabled | Security Defaults | 1.1.1 L1 | IM-6 |
| AZ-ID-02: ≥1 enabled Conditional Access policy | Conditional Access | 1.2.x L1 | IM-7 |
| AZ-ID-03: CA policy requires MFA for all users | Conditional Access | 1.2.3 L1 | IM-6 |
| AZ-ID-04: CA policy blocks legacy authentication | Conditional Access | 1.2.6 L1 | IM-7 |
| AZ-ID-05: Guest user access restricted (level ≤1) | Guest Access | 1.11 L1 | PA-3 |
| AZ-ID-06: Guest invitation restricted to admins | Guest Access | 1.12/1.13 L1 | PA-3 |
| AZ-ID-07: Users cannot create new Azure AD tenants | User Settings | 1.10 L1 | GS-1 |
| AZ-ID-08: Users cannot register applications | User Settings | 1.9 L1 | IM-3 |
| AZ-ID-09: Legacy user consent policy not assigned | User Settings | 1.8 L1 | PA-5 |
| AZ-ID-10: Global Admin count is 2–4 | Privileged Access | 1.14.1 L1 | PA-1 |
| AZ-ID-11: No external/guest Global Administrator | Privileged Access | — | PA-1 |
| AZ-ID-12: PIM in use (eligible assignments >0) | PIM | 1.15.1 L2 | PA-7 |
| AZ-ID-13: PIM GA activation requires MFA | PIM | 1.15.2 L1 | PA-7 |
| AZ-ID-14: PIM GA activation requires justification | PIM | 1.15.3 L1 | PA-7 |
| AZ-ID-15: PIM GA activation requires approval | PIM | 1.15.4 L2 | PA-7 |
| AZ-ID-16: CA: sign-in risk policy configured | Identity Protection | 1.5 L2 | IM-6 |
| AZ-ID-17: CA: user risk policy configured | Identity Protection | 1.6 L2 | IM-6 |

Checks AZ-ID-01 and AZ-ID-02 together cover the **Security Defaults vs. Conditional Access**
trade-off: a production tenant with CA deployed will intentionally fail AZ-ID-01 (SD is
disabled) but should pass AZ-ID-02 through AZ-ID-04. Identity Protection checks (AZ-ID-16/17)
and PIM checks (AZ-ID-12–15) require **Azure AD P2** licensing.

## Prerequisites

| Requirement | Notes |
| :--- | :--- |
| `az` CLI | [Install Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) |
| `az login` | Must be completed before running the script |
| Entra ID role | **Global Reader** (covers all Phase 1 checks) or at minimum **Security Reader** + **Directory Readers** |
| Azure AD P2 | Required for PIM checks (AZ-ID-12–15) and Identity Protection checks (AZ-ID-16/17); Phase 1 checks not requiring P2 still run |

## Easy run — one command

```powershell
# From the scripts/powershell directory, after az login
.\Invoke-AzurePostureAudit.ps1
```

The report lands in the **script's own folder** (`$PSScriptRoot`) as
`azposture-<timestamp>.json`, `.ndjson` and `.csv`. Use `-OutputPath D:\Evidence` to redirect.

## Parameters

```powershell
# Stricter grading — fail only when CIS AND MCSB AND best-practice all pass
.\Invoke-AzurePostureAudit.ps1 -Bar Strictest -OutputPath D:\Evidence

# Target a specific tenant (multi-tenant scenario)
.\Invoke-AzurePostureAudit.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# Show only failures and errors
.\Invoke-AzurePostureAudit.ps1 | Where-Object Status -ne 'Pass'

# Exit 1 on any Fail, exit 2 on any Error (for CI / automated attestation)
.\Invoke-AzurePostureAudit.ps1 -FailOn FailOrError -Quiet
```

| Parameter | Default | Description |
| :--- | :--- | :--- |
| `-TargetEnvironment` | `Test` | Recorded in the report; does not change read-only behaviour |
| `-Bar` | `BestPractice` | `BestPractice` passes on best-practice expectation met; `Strictest` requires all frameworks to pass |
| `-CatalogPath` | Auto-resolved | Override the catalog JSON path |
| `-TenantId` | (signed-in default) | Target a specific Entra ID tenant |
| `-OutputPath` | Script folder | Write reports here; `''` skips file output |
| `-Format` | `Json,Ndjson,Csv` | One or more output formats |
| `-FailOn` | `None` | `Fail` → exit 1 on any failure; `FailOrError` → also exit 2 on errors |
| `-Quiet` | Off | Suppress console output |

## Report structure and result schema

Each check produces one result row. Results are also written to JSON, NDJSON and CSV:

| Field | Values | Notes |
| :--- | :--- | :--- |
| `Id` | `AZ-ID-xx` | Catalog check ID |
| `Status` | `Pass / Fail / Error / NotApplicable` | Overall status (per `-Bar`) |
| `Cis` | `Pass / Fail / Error / n/a` | CIS benchmark verdict |
| `Mcsb` | `Pass / Fail / Error / n/a` | MCSB verdict |
| `BestPractice` | `Pass / Fail / Error / n/a` | Best-practice verdict (pass bar at `BestPractice`) |
| `Expected` | Human-readable expectation | All framework expectations |
| `Actual` | Observed value | From the fact collector |
| `Detail` | Collector error or per-framework result | Diagnostic information |

The JSON report envelope carries `schema: "cc.azposture.report/1"` and `summary.scorePct`
(percentage of evaluated checks that passed, excluding Error and NotApplicable).

!!! note "Security Defaults vs. Conditional Access"
    AZ-ID-01 (Security Defaults) is expected to fail on enterprise tenants where Conditional
    Access has replaced it. A low AZ-ID-01 score with high AZ-ID-02/03/04 scores is the correct
    posture for a P1/P2-licensed tenant. Review the intent of each failing check; not every
    failure is a gap.

## Catalog and phased roadmap

The Phase 1 catalog is `scripts/cis/catalogs/azure/azure-identity-posture-v1.json`. Each check
carries:

- **`collector`** key — the fact the engine looks for in the context (e.g. `Entra.SecurityDefaults.IsEnabled`)
- **`frameworks`** block — `cis`, `mcsb` and `bestPractice` each with an `expect` object using the
  same operator model as the CIS Windows and AD posture engines (`eq`, `range`, `in`, `regex`, ...)
- **`remediation`** link — the Microsoft Learn or CIS reference

```json
{
  "id": "AZ-ID-03",
  "title": "A Conditional Access policy requires MFA for all users",
  "category": "Conditional Access",
  "collector": "Entra.ConditionalAccess.HasMfaAllUsers",
  "frameworks": {
    "cis":         { "id": "1.2.3 (L1)", "expect": { "op": "eq", "value": "True" } },
    "mcsb":        { "id": "IM-6",       "expect": { "op": "eq", "value": "True" } },
    "bestPractice":{ "source": "CIS/MCSB","expect": { "op": "eq", "value": "True" } }
  }
}
```

**Planned phases** (future work packages):

| Phase | Scope | Checks |
| :--- | :--- | :--- |
| **Phase 1 (this page)** | Identity / Entra ID | CA, MFA, privileged roles, PIM |
| Phase 2 | Subscriptions | Azure Policy compliance, Defender for Cloud secure score |
| Phase 3 | Storage / Network / Key Vault | Public access, Key Vault firewall, NSG defaults |
| Phase 4 | Logging | Diagnostic settings, activity log retention, Sentinel workspace |

See the roadmap section in [Azure Security Baseline](../../hardening/cloud-azure-security-baseline.md).

## How the engine works

The engine (`scripts/powershell/AzurePosture/AzurePosture.psm1`) follows the same pattern as the
[AD posture engine](../../assurance/ad-environment-posture-audit.md):

1. **`Get-AzurePostureContext`** — collects all facts with `az rest` Graph v1.0 calls into a
   `$context.Facts` hashtable; errors are recorded in `$context.Errors` so collection failures
   never abort the run.
2. **`Invoke-AzurePostureCheck`** — reads one fact, evaluates it against every declared framework
   expectation using `Test-CisExpectation` (shared with the CIS Windows engine), returns a result
   row with a per-framework verdict and an overall `Status`.

## Permissions

The minimum Entra ID built-in role is **Global Reader**. If you want to restrict further:

| Check group | Required permission |
| :--- | :--- |
| Security Defaults, CA policies, Authorization Policy | `Policy.Read.All` or Security Reader |
| Directory Roles (GA members) | `RoleManagement.Read.Directory` or Directory Readers |
| PIM eligible assignments | `PrivilegedAccess.Read.AzureAD` (requires P2) |
| PIM role management policies | `RoleManagementPolicy.Read.AzureAD` (requires P2) |

The tenant metadata call (`/organization`) requires `Organization.Read.All`; it is best-effort —
a failure here does not stop the audit.

## Detect it

| Indicator | Detection source |
| :--- | :--- |
| Admin sign-in from new location / outside CA policy | [KQL: Logon & Identity Anomalies](../../detection/kql/logon-identity.md) |
| Privileged role assignment outside PIM | [Sigma: Cloud Identity & Entra Rules](../../detection/sigma/cloud-identity-rules.md) |
| Legacy auth blocked by CA (volume baseline) | [KQL: Logon & Identity Anomalies](../../detection/kql/logon-identity.md) |
| Guest user granted privileged role | [Sigma: Cloud Identity & Entra Rules](../../detection/sigma/cloud-identity-rules.md) |

## Harden it

| Finding | Hardening guidance |
| :--- | :--- |
| Security Defaults off, no CA | [Azure Security Baseline — Identity & Access Controls](../hardening/cloud-azure-security-baseline.md) |
| Legacy auth not blocked | [Azure Security Baseline — Conditional Access](../hardening/cloud-azure-security-baseline.md) |
| Guest access too permissive | [Azure Security Baseline — Identity & Access Controls](../hardening/cloud-azure-security-baseline.md) |
| No PIM / permanent GA accounts | [Identity & Directory Query Cookbook — Privileged Roles](../../references/identity-directory-query-cookbook.md) |

## Related

- [Posture Audit (Workstation/Server/AD)](posture-audit.md) — Windows and AD posture umbrella
- [AD Environment Posture Audit](ad-environment-posture-audit.md) — on-prem AD engine
- [Azure Security Baseline](../../hardening/cloud-azure-security-baseline.md) — hardening controls
- [Azure NSG Compliance](azure-nsg-compliance.md) — network security group audit
- [Identity & Directory Query Cookbook](../../references/identity-directory-query-cookbook.md) — Entra ID Graph queries
- [CIS Microsoft Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Microsoft Cloud Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/)
- [Microsoft Learn: Secure your Azure environment](https://learn.microsoft.com/azure/security/)
