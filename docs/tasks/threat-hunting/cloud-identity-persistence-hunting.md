---
title: Hunting Cloud Identity Persistence in Entra ID and Microsoft 365
type: workflow
platforms:
  - Entra ID
  - Microsoft 365
  - Azure
  - Microsoft Defender
  - Splunk
languages:
  - PowerShell
  - KQL
  - SPL
tasks:
  - Threat Hunting
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - entra-id
  - cloud
  - persistence
  - service-principal
  - oauth
  - app-role
  - audit-logs
---

# Hunting Cloud Identity Persistence in Entra ID and Microsoft 365

Adversaries infiltrating Microsoft 365 and Entra ID environments establish stealthy persistence by granting administrative app roles, registering backdoored client secrets on service principals, and installing illicit OAuth consent apps that survive user password resets.

---

## 1. Key Cloud Persistence Attack Vectors

| Attack Vector | MITRE ATT&CK | Telemetry / Audit Operation | Suspicious Indicator |
| :--- | :--- | :--- | :--- |
| **Service Principal Secret Addition** | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | `Add service principal credentials` | New client certificate or high-duration password added to an existing enterprise app. |
| **Illicit OAuth Consent Grant** | [T1528](https://attack.mitre.org/techniques/T1528/) | `Consent to application` | Non-admin user grants offline access, `Mail.ReadWrite`, or `Directory.Read.All` to unverified multitenant app. |
| **Directory Role Elevation** | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | `Add member to role` | User or Service Principal added to Global Administrator or Privileged Role Administrator outside PIM. |
| **Federation Trust Modification** | [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | `Set domain authentication` | Modified signing certificate or domain federation settings (Golden SAML attack). |

---

## 2. Threat Hunting Queries

### Microsoft Defender XDR (KQL): Service Principal Credential Addition

```kql
CloudAppEvents
| where ActionType in~ ("Add service principal credentials.", "Update service principal credentials.")
| extend TargetAppName = tostring(RawEventData.Target[0].DisplayName)
| extend InitiatorUser = tostring(RawEventData.UserId)
| extend IP = tostring(RawEventData.ClientIP)
| project Timestamp, ActionType, TargetAppName, InitiatorUser, IP, RawEventData
| order by Timestamp desc
```

### Microsoft Sentinel / Defender (KQL): Illicit OAuth Consent Grants

```kql
AuditLogs
| where OperationName in~ ("Consent to application", "Add delegated permission grant")
| extend AppDisplayName = tostring(TargetResources[0].DisplayName)
| extend Permissions = tostring(TargetResources[0].ModifiedProperties)
| where Permissions has_any ("Mail.Read", "Mail.ReadWrite", "MailboxSettings.ReadWrite", "Directory.ReadWrite.All", "FullControl")
| project TimeGenerated, OperationName, AppDisplayName, InitiatedBy = tostring(InitiatedBy.User.UserPrincipalName), Permissions
| order by TimeGenerated desc
```

### Splunk (SPL): Privileged Directory Role Assignment

```spl
index=azure_audit OperationName="Add member to role"
| spath path=TargetResources{}.ModifiedProperties{}.NewValue output=RoleName
| search RoleName IN ("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator")
| table _time OperationName RoleName InitiatedBy.User.UserPrincipalName TargetResources{}.UserPrincipalName
| sort - _time
```

---

## 3. PowerShell Audit & Hunting Scripts

Using the `Microsoft.Graph` PowerShell SDK to enumerate active credentials across all service principals:

```powershell
# Connect with AuditLog and Application read scopes
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "AuditLog.Read.All"

# 1. Enumerate all applications with credentials expiring > 1 year or added recently
$Apps = Get-MgApplication -All
$CredentialAudit = foreach ($app in $Apps) {
    # Check Password Credentials (Secrets)
    foreach ($pwd in $app.PasswordCredentials) {
        [PSCustomObject]@{
            AppId         = $app.AppId
            DisplayName   = $app.DisplayName
            KeyType       = "Secret"
            StartDateTime = $pwd.StartDateTime
            EndDateTime   = $pwd.EndDateTime
            KeyId         = $pwd.KeyId
        }
    }
    # Check Key Credentials (Certificates)
    foreach ($cert in $app.KeyCredentials) {
        [PSCustomObject]@{
            AppId         = $app.AppId
            DisplayName   = $app.DisplayName
            KeyType       = "Certificate"
            StartDateTime = $cert.StartDateTime
            EndDateTime   = $cert.EndDateTime
            KeyId         = $cert.KeyId
        }
    }
}

$CredentialAudit | Sort-Object StartDateTime -Descending | Select-Object -First 30

# 2. Check for Service Principals with Global Administrator role
$GlobalAdminRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Global Administrator" }
Get-MgDirectoryRoleMember -DirectoryRoleId $GlobalAdminRole.Id | Where-Object {
    $_."@odata.type" -eq "#microsoft.graph.servicePrincipal"
} | Select-Object Id, DisplayName
```

---

## 4. Remediation & Hardening Protocol

1. **Enforce Entra ID Privileged Identity Management (PIM)**: Require step-up MFA and approval workflow for all directory role activations; eliminate standing administrative assignments.
2. **Restrict User Consent for Applications**: Set `Consent and permissions` in Entra ID to `Do not allow user consent`. Require administrator review for all OAuth permission requests.
3. **Automate Service Principal Expiration Policies**: Enforce maximum lifetime limits (e.g., 90 to 180 days) for client secrets and rotate high-privilege automation credentials.
