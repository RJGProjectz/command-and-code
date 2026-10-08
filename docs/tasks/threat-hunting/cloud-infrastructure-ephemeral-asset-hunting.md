---
title: Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies
type: workflow
platforms:
  - Entra ID
  - Microsoft 365
  - Azure
  - Microsoft Defender
  - Splunk
languages:
  - KQL
  - SPL
  - PowerShell
tasks:
  - Threat Hunting
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - threat-hunting
  - cloud-identity
  - oauth
  - service-principal
  - ephemeral-assets
  - pim
  - entra-id
---

# Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies

As organizations transition to hybrid environments, adversaries bypass endpoint telemetry by targeting identity control planes (Entra ID, Microsoft 365, Azure). Common cloud persistence and defense evasion techniques include illicit OAuth consent grants, backdooring service principal credentials, exploiting Privileged Identity Management (PIM), and rapidly deploying and destroying ephemeral cloud compute resources.

---

## 1. Cloud Attack Surface Matrix

| Adversary TTP | MITRE ATT&CK | Cloud Telemetry Source | Threat Indicator |
| :--- | :--- | :--- | :--- |
| **Illicit Consent Grant** | T1528 / T1098.003 | Entra ID AuditLogs (`Consent to application`) | Third-party app granted broad Graph scopes (`Mail.ReadWrite`, `Directory.ReadWrite.All`) |
| **Service Principal Backdoor** | T1098.001 | Entra ID AuditLogs (`Update application`) | New password credentials or certificates added to dormant or highly privileged App Registrations |
| **PIM Activation Outlier** | T1078.004 | Entra ID AuditLogs (`Add member to role in PIM`) | Role activation outside business hours or without matching change management ticket |
| **Ephemeral Compute Abuse** | T1578.002 / T1496 | Azure Activity Logs (`Microsoft.Compute/virtualMachines/write`) | VM provisioned, high network egress/CPU burst, and destroyed within $< 4$ hours |

---

## 2. Hunt 1: Illicit Consent Grants & High-Privilege OAuth Scopes

Adversaries spear-phish users into approving malicious OAuth enterprise applications. Once consented, the application accesses email, files, or directory data directly via Microsoft Graph API without needing the user's password or MFA.

### Microsoft Sentinel / Defender XDR (KQL): High-Privilege OAuth Consent

```kql
// Detect users or administrators granting risky permissions to multi-tenant or external OAuth applications
let SensitiveScopes = dynamic([
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "Files.ReadWrite.All", "User.ReadWrite.All", "Domain.ReadWrite.All"
]);
AuditLogs
| where LoggedByService == "Core Directory"
| where OperationName in~ ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName),
         InitiatorUser = tostring(InitiatedBy.user.userPrincipalName),
         TargetApp = tostring(TargetResources[0].displayName)
| mv-expand TargetResources[0].modifiedProperties
| extend PropName = tostring(TargetResources_0_modifiedProperties.displayName),
         NewValue = tostring(TargetResources_0_modifiedProperties.newValue)
| where PropName in ("ConsentAction.Permissions", "Scope", "DelegatedPermissionGrant.Scope")
| extend ScopesList = split(NewValue, " ")
| mv-expand Scope = ScopesList
| where Scope in~ (SensitiveScopes)
| project TimeGenerated, InitiatorUser, TargetApp, Scope, NewValue, CorrelationId
| summarize FirstConsent = min(TimeGenerated), UniqueUsers = dcount(InitiatorUser), Users = make_set(InitiatorUser) 
    by TargetApp, tostring(Scope)
| sort by UniqueUsers asc
```

### Splunk (SPL): Anomalous OAuth Grants in Entra ID

```spl
index=azure sourcetype="azure:aad:audit" operationName="Consent to application"
| spath input=targetResources output=target_app path={}.displayName
| spath input=targetResources output=modified_props path={}.modifiedProperties
| mvexpand modified_props
| spath input=modified_props output=prop_name path=displayName
| spath input=modified_props output=new_val path=newValue
| search prop_name="ConsentAction.Permissions" (new_val="*Mail.Read*" OR new_val="*Directory.ReadWrite*" OR new_val="*Files.ReadWrite*")
| stats count, earliest(_time) as FirstSeen, latest(_time) as LastSeen, values(caller) as ConsentingUsers by target_app, new_val
| sort - count
```

---

## 3. Hunt 2: Service Principal Credential Backdoors

Adversaries who gain Global Administrator or Application Administrator privileges often generate new client secrets or certificates on existing multi-tenant service principals to maintain persistent access undetected.

### Microsoft Sentinel (KQL): New Secrets Added to Existing Service Principals

```kql
// Hunt for secret or certificate additions to application objects
AuditLogs
| where OperationName in~ (
    "Update application – Certificates and secrets management ",
    "Add service principal credentials",
    "Add owner to application"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
         TargetAppName = tostring(TargetResources[0].displayName),
         TargetAppId = tostring(TargetResources[0].id)
| mv-expand TargetResources[0].modifiedProperties
| extend PropName = tostring(TargetResources_0_modifiedProperties.displayName),
         NewValue = tostring(TargetResources_0_modifiedProperties.newValue),
         OldValue = tostring(TargetResources_0_modifiedProperties.oldValue)
| where PropName in ("KeyDescription", "AppAddress", "Credential")
| project TimeGenerated, InitiatedByUser, TargetAppName, TargetAppId, PropName, NewValue
| sort by TimeGenerated desc
```

### PowerShell Verification: Enumerate Enterprise App Credentials

```powershell
# Connect to Microsoft Graph and inspect recent credential updates
# Requires Microsoft.Graph.Applications module
Import-Module Microsoft.Graph.Applications -ErrorAction SilentlyContinue

$Apps = Get-MgApplication -All
foreach ($App in $Apps) {
    $PasswordCredentials = $App.PasswordCredentials
    $KeyCredentials = $App.KeyCredentials
    
    if ($PasswordCredentials.Count -gt 0) {
        $RecentCreds = $PasswordCredentials | Where-Object { $_.StartDateTime -gt (Get-Date).AddDays(-30) }
        if ($RecentCreds) {
            [PSCustomObject]@{
                DisplayName = $App.DisplayName
                AppId       = $App.AppId
                CredCount   = $PasswordCredentials.Count
                RecentAdd   = $RecentCreds.Count
                Created     = $RecentCreds.StartDateTime
            }
        }
    }
}
```

---

## 4. Hunt 3: Ephemeral Cloud Compute Abuse

Threat actors deploy high-performance virtual machine instances (e.g., GPU nodes) for cryptomining, large-scale password cracking, or exfiltration relays, and subsequently delete them before administrative audits occur.

### Azure Activity Logs (KQL): Short-Lived Virtual Machines ($< 4\text{ hours}$)

```kql
// Identify VMs created and destroyed within an ephemeral timeframe
let StartWindow = ago(14d);
let VM_Creations = AzureActivity
| where TimeGenerated >= StartWindow
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/write" and ActivityStatusValue =~ "Success"
| project CreationTime = TimeGenerated, ResourceId = tolower(_ResourceId), Caller = Caller, ResourceGroup;
let VM_Deletions = AzureActivity
| where TimeGenerated >= StartWindow
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/delete" and ActivityStatusValue =~ "Success"
| project DeletionTime = TimeGenerated, ResourceId = tolower(_ResourceId), DeletingCaller = Caller;
VM_Creations
| join kind=inner (VM_Deletions) on ResourceId
| extend LifespanHours = datetime_diff('hour', DeletionTime, CreationTime)
| where LifespanHours <= 4
| project ResourceId, Caller, DeletingCaller, CreationTime, DeletionTime, LifespanHours, ResourceGroup
| sort by LifespanHours asc
```

---

## 5. Hunt 4: Privileged Identity Management (PIM) Outliers

Privileged Identity Management allows just-in-time (JIT) role elevation. Threat actors abusing compromised administrative accounts may activate roles (e.g., Global Administrator, Security Administrator) during off-hours to avoid manual peer oversight.

### KQL: Off-Hours PIM Role Elevation

```kql
AuditLogs
| where LoggedByService == "PIM"
| where OperationName has "Add member to role in PIM completed"
| extend ElevatingUser = tostring(TargetResources[0].userPrincipalName),
         RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| extend EventHour = hourofday(TimeGenerated),
         EventDay = dayofweek(TimeGenerated)
// Flag weekend activations or nighttime hours (10 PM to 5 AM UTC)
| where EventHour between (22 .. 24) or EventHour between (0 .. 5) or EventDay in (0d, 6d)
| project TimeGenerated, ElevatingUser, RoleName, EventHour, CorrelationId
| summarize Count = count(), Roles = make_set(RoleName) by ElevatingUser, bin(TimeGenerated, 1d)
| sort by Count desc
```

---

## 6. Incident Triage Workflow

If anomalous OAuth grants or service principal credentials are confirmed:

1. **Immediate Revocation:** Invalidate refresh tokens and revoke user sessions:
   ```powershell
   Revoke-MgUserSignOut -UserId "<USER_UPN>"
   ```
2. **Remove Credential:** Delete the unauthorized secret from the target App Registration via Microsoft Entra admin center or Graph API.
3. **Audit Token Issuance:** Search Entra ID sign-in logs for non-interactive sign-ins utilizing the malicious application ID (`AppId`) to determine what data was accessed.
