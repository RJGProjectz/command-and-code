---
title: Investigation Playbook — Compromised Service Principal
type: workflow
platforms:
  - Entra ID
  - Azure
languages:
  - KQL
  - PowerShell
tasks:
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - playbook
  - entra
  - service-principal
  - non-human-identity
---

# Investigation Playbook — Compromised Service Principal

Investigation and emergency containment procedure for compromised non-human identities, App Registrations, and Managed Identities in Entra ID.

---

## 1. Objective & Scope

- **What is being investigated**: Unauthorized addition of client credentials/certificates to Entra ID applications or abnormal API token utilization.
- **Why it matters**: Service Principals bypass MFA entirely and frequently possess high-privilege directory permissions (`Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`), representing silent persistence vectors (MITRE ATT&CK [T1078.004](https://attack.mitre.org/techniques/T1078/004/)).
- **Target Systems**: Entra ID App Registrations, Enterprise Applications, Azure Key Vault.

---

## 2. Telemetry Queries

### Entra Audit Logs — Rogue Secret / Certificate Addition

```kql
AuditLogs
| where OperationName == "Update application - Certificates and secrets management"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend AppDisplayName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
| project TimeGenerated, OperationName, Actor, AppDisplayName, AppId, TargetResources
| order by TimeGenerated desc
```

### Sign-in Logs — Non-Interactive Service Principal Activity

```kql
AADServicePrincipalSignInLogs
| where ServicePrincipalId == "<TARGET_SERVICE_PRINCIPAL_ID>"
| project TimeGenerated, ServicePrincipalName, IPAddress, Location, ResourceDisplayName
| summarize RequestCount = count() by IPAddress, Location, bin(TimeGenerated, 1h)
```

---

## 3. Analysis & Triaging

- **Actor Validation**: Was the administrator who added the credential an authorized member of Cloud Engineering during a scheduled change ticket?
- **Key Vault Inspection**: Was the secret generated through automated Infrastructure-as-Code pipelines or manual GUI portal generation?
- **Anomalous IP Ranges**: Is the Service Principal authenticating from public proxy/VPN ranges instead of corporate data centers or cloud runners?

---

## 4. Emergency Containment

```powershell
# 1. Instantly disable the Enterprise Application in Entra ID
Update-MgServicePrincipal -ServicePrincipalId "<SP_OBJECT_ID>" -AccountEnabled:$false

# 2. Invalidate active tokens via Microsoft Graph
# Revoke all credentials on the parent App Registration
$App = Get-MgApplication -ApplicationId "<APP_OBJECT_ID>"
Get-MgApplicationPasswordCredential -ApplicationId $App.Id | ForEach-Object {
    Remove-MgApplicationPasswordCredential -ApplicationId $App.Id -KeyId $_.KeyId
}
```
