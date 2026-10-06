---
title: Entra ID
platforms: [Microsoft 365, Entra ID]
languages: [PowerShell]
tasks: [Incident Response, Investigation, Administration]
category: Identity
tags: [entra id, azure ad, microsoft graph, revoke sessions, sign-in logs, mfa, roles]
aliases: [azure ad, revoke sessions, disable user entra, sign-in logs powershell, Get-MgUser, auth methods]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Entra ID

Examples use the **Microsoft Graph PowerShell SDK** (`Install-Module Microsoft.Graph`). The older AzureAD and MSOnline modules are retired.

## Connect

```powershell
Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All', 'Directory.Read.All'
Get-MgContext
```

Request only the scopes the task needs. Write actions need write scopes (e.g. `User.ReadWrite.All`, `User.RevokeSessions.All`).

## Look up a user

```powershell
Get-MgUser -UserId '<USER>@<DOMAIN>' -Property Id, DisplayName, AccountEnabled, CreatedDateTime, SignInActivity, OnPremisesSyncEnabled |
    Select-Object DisplayName, AccountEnabled, CreatedDateTime, OnPremisesSyncEnabled,
        @{ Name = 'LastSignIn'; Expression = { $_.SignInActivity.LastSignInDateTime } }
```

`Get-MgUser` returns only a default property set unless you name properties with `-Property`. `SignInActivity` requires `AuditLog.Read.All` and Entra ID P1 or higher.

## Contain a compromised account

```powershell
Update-MgUser -UserId '<USER>@<DOMAIN>' -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId '<USER>@<DOMAIN>'
```

Revoking invalidates refresh tokens; access tokens already issued remain valid until they expire (typically up to about an hour, unless Continuous Access Evaluation applies). For hybrid accounts (`OnPremisesSyncEnabled = True`), disable in on-premises AD as well or the next sync can re-enable the account.

**Portal:** Entra admin center → Users → select user → **Revoke sessions**.

## Review authentication methods

```powershell
Get-MgUserAuthenticationMethod -UserId '<USER>@<DOMAIN>' |
    Select-Object Id, @{ Name = 'Type'; Expression = { $_.AdditionalProperties['@odata.type'] } }
```

An attacker-registered MFA method (new phone, authenticator app) is a persistence mechanism ([T1098.005](https://attack.mitre.org/techniques/T1098/005/)).

## Sign-in logs

```powershell
Get-MgAuditLogSignIn -Filter "userPrincipalName eq '<USER>@<DOMAIN>'" -Top 50 |
    Select-Object CreatedDateTime, AppDisplayName, IPAddress, ClientAppUsed,
        @{ Name = 'Result'; Expression = { $_.Status.ErrorCode } },
        @{ Name = 'City'; Expression = { $_.Location.City } },
        @{ Name = 'Country'; Expression = { $_.Location.CountryOrRegion } }
```

`ErrorCode` 0 = success. For large-scale analysis use [KQL SigninLogs](../../detection/kql/logon-identity.md#entra-id-sign-in-logs).

## Directory audit events

```powershell
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role'" -Top 50 |
    Select-Object ActivityDateTime, ActivityDisplayName,
        @{ Name = 'By'; Expression = { $_.InitiatedBy.User.UserPrincipalName } },
        @{ Name = 'Target'; Expression = { $_.TargetResources[0].UserPrincipalName } }
```

## Privileged role members

```powershell
Get-MgDirectoryRole | ForEach-Object {
    $role = $_
    Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
        [pscustomobject]@{ Role = $role.DisplayName; Member = $_.AdditionalProperties['userPrincipalName'] }
    }
} | Sort-Object Role
```

`Get-MgDirectoryRole` lists only **activated** roles. PIM-eligible assignments are not shown here.

## Application consent grants

```powershell
Get-MgOauth2PermissionGrant -All | Select-Object ClientId, ConsentType, PrincipalId, Scope
```

Delegated grants with broad scopes such as `Mail.Read`, `Mail.ReadWrite` or `Files.ReadWrite.All` to unfamiliar apps are a consent-phishing indicator ([T1528](https://attack.mitre.org/techniques/T1528/)).

## Risky users (Entra ID P2)

```powershell
Get-MgRiskyUser -Filter "riskState eq 'atRisk'" | Select-Object UserPrincipalName, RiskLevel, RiskLastUpdatedDateTime
```

## Related

- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)
- [Conditional Access](conditional-access.md)
- [KQL sign-in and audit logs](../../detection/kql/logon-identity.md)

## Sources

- [Microsoft Graph PowerShell overview](https://learn.microsoft.com/powershell/microsoftgraph/overview)
- [Revoke-MgUserSignInSession](https://learn.microsoft.com/powershell/module/microsoft.graph.users.actions/revoke-mgusersigninsession)
- [Sign-in error codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)
