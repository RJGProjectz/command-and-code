---
title: Conditional Access
platforms: [Microsoft 365, Entra ID]
languages: [PowerShell, KQL]
tasks: [Administration, Hardening, Investigation, Troubleshooting]
category: Identity
tags: [conditional access, entra id, policies, named locations, sign-in troubleshooting]
aliases: [CA policies, why was sign-in blocked, report-only policy, named locations, what if tool]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Conditional Access

## Where is the setting?

=== "Portal"

    ```text
    Entra admin center (entra.microsoft.com)
    → Conditional Access
    → Policies | Named locations | Authentication strengths
    ```

    Menu groupings move between releases; searching *Conditional Access* in the portal always works.

=== "PowerShell"

    ```powershell
    Connect-MgGraph -Scopes 'Policy.Read.All'
    Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime
    ```

=== "Graph API"

    ```text
    GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
    ```

`State` values: `enabled`, `disabled`, `enabledForReportingButNotEnforced` (report-only).

## Export all policies (change tracking / backup)

```powershell
$out = 'C:\Cases\ca-policies'
New-Item -ItemType Directory -Path $out -Force | Out-Null
Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object {
    $safeName = $_.DisplayName -replace '[\\/:*?"<>|]', '_'
    $_ | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $out "$safeName.json") -Encoding utf8
}
```

Committing these JSON exports to Git gives you a diffable history of policy changes.

## Named locations

```powershell
Get-MgIdentityConditionalAccessNamedLocation |
    Select-Object DisplayName, @{ Name = 'Type'; Expression = { $_.AdditionalProperties['@odata.type'] } }
```

## Why was this sign-in blocked?

1. Entra admin center → **Sign-in logs** → select the sign-in → **Conditional Access** tab shows each policy and its result.
2. Use the **What If** tool (Conditional Access → Policies → What If) to simulate user, app, location and device.
3. Query at scale with KQL:

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ConditionalAccessStatus == "failure"
| mv-expand Policy = ConditionalAccessPolicies
| where tostring(Policy.result) == "failure"
| summarize Failures = count() by PolicyName = tostring(Policy.displayName), UserPrincipalName
| order by Failures desc
```

Sign-in error `53003` = blocked by Conditional Access.

## Detect policy changes

Audit log activities: `Add conditional access policy`, `Update conditional access policy`, `Delete conditional access policy`.

```kql
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has "conditional access policy"
| project TimeGenerated, OperationName, By = tostring(InitiatedBy.user.userPrincipalName), Policy = tostring(TargetResources[0].displayName)
```

## Related

- [Entra ID](entra.md)
- [KQL logons and identity](../../detection/kql/logon-identity.md)

## Sources

- [List conditionalAccessPolicies](https://learn.microsoft.com/graph/api/conditionalaccessroot-list-policies)
- [Conditional Access What If tool](https://learn.microsoft.com/entra/identity/conditional-access/what-if-tool)
