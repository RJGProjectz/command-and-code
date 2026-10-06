---
title: KQL Logon and Identity Hunting
platforms: [Microsoft Defender, Entra ID, Microsoft 365, Windows]
languages: [KQL]
tasks: [Threat Hunting, Investigation, Incident Response, Detection Engineering]
category: Authentication
tags: [kql, devicelogonevents, identitylogonevents, signinlogs, auditlogs, password spray, brute force]
aliases: [failed logins kql, password spray detection, signinlogs, entra sign-in kql, rdp logons kql, role assignment kql]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# KQL Logon and Identity Hunting

| Table | Source | Time column |
| --- | --- | --- |
| `DeviceLogonEvents` | Defender for Endpoint (logons on devices) | `Timestamp` |
| `IdentityLogonEvents` | Defender for Identity (domain controllers) and cloud apps | `Timestamp` |
| `SigninLogs` | Entra ID sign-ins — Sentinel / Log Analytics | `TimeGenerated` |
| `AuditLogs` | Entra ID directory changes — Sentinel / Log Analytics | `TimeGenerated` |

Entra sign-in data is also available in Defender XDR advanced hunting through its own table (historically `AADSignInEventsBeta`); confirm the current table name in your tenant's schema browser.

## Failed logons on devices

```kql
DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Failures = count(), Accounts = dcount(AccountName), AccountSample = make_set(AccountName, 10)
          by DeviceName, RemoteIP, LogonType, FailureReason
| order by Failures desc
```

`LogonType` values include `Interactive`, `Network`, `RemoteInteractive` (RDP), `Batch`, `Service`, `Unlock`, `CachedInteractive`.

## Successful RDP logons

```kql
DeviceLogonEvents
| where Timestamp > ago(7d)
| where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
| summarize Logons = count(), First = min(Timestamp), Last = max(Timestamp) by DeviceName, AccountDomain, AccountName, RemoteIP
```

## Domain authentication (Defender for Identity)

```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonFailed"
| summarize Failures = count(), Targets = dcount(AccountUpn) by IPAddress, DeviceName, Protocol
| where Targets > 10
```

Many accounts failing from one source = password spray ([T1110.003](https://attack.mitre.org/techniques/T1110/003/)).

## Entra ID sign-in logs

`ResultType` is a **string**; `"0"` is success.

| ResultType | Meaning |
| --- | --- |
| 50126 | Invalid username or password |
| 50053 | Account locked (smart lockout) or sign-in from malicious IP blocked |
| 50074 / 50076 | Strong authentication (MFA) required |
| 500121 | MFA failed / not completed |
| 53003 | Blocked by Conditional Access |

### Password spray against Entra ID

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "50126"
| summarize Users = dcount(UserPrincipalName), Attempts = count(), UserSample = make_set(UserPrincipalName, 20) by IPAddress
| where Users >= 10
| order by Users desc
```

### Successful sign-in after many failures

```kql
let failures = SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == "50126"
    | summarize FailedAttempts = count() by UserPrincipalName, IPAddress
    | where FailedAttempts >= 5;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == "0"
| join kind=inner failures on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, FailedAttempts, AppDisplayName,
          City = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)
```

### One user's sign-in history

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where UserPrincipalName =~ "<USER>@<DOMAIN>"
| project TimeGenerated, ResultType, ResultDescription, AppDisplayName, ClientAppUsed, IPAddress,
          Country = tostring(LocationDetails.countryOrRegion), Device = tostring(DeviceDetail.displayName),
          ConditionalAccessStatus, AuthenticationRequirement
| order by TimeGenerated desc
```

**What to look for:** new countries or ASNs, legacy `ClientAppUsed` values (IMAP, POP, SMTP, "Other clients"), single-factor successes for accounts that normally use MFA.

## Entra ID directory changes

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add service principal credentials", "Consent to application",
                          "Reset user password", "User registered security info")
| project TimeGenerated, OperationName, Result,
          By = tostring(InitiatedBy.user.userPrincipalName),
          Target = tostring(TargetResources[0].userPrincipalName),
          TargetName = tostring(TargetResources[0].displayName)
| order by TimeGenerated desc
```

`in` requires exact operation names. If one returns nothing, list what your tenant records: `AuditLogs | summarize count() by OperationName`.

## Related

- [Account Compromise workflow](../../tasks/incident-response/account-compromise.md)
- [Failed Authentication workflow](../../tasks/investigation/failed-authentication.md)
- [SPL authentication](../spl/windows-events.md#failed-logons-4625)
- [Entra ID](../../platforms/microsoft-365/entra.md)

## Sources

- [DeviceLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicelogonevents-table)
- [IdentityLogonEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table)
- [SigninLogs schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs)
- [Entra authentication error codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)
