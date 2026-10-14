---
title: Azure Audit Logging (Activity Log & Diagnostic Settings)
platforms: [Azure, Entra ID]
languages: [Bash, PowerShell, KQL]
tasks: [Investigation, Incident Response, Forensics, Hardening]
category: Logging
tags: [azure, activity log, diagnostic settings, azureactivity, entra sign-in logs, log retention, audit]
aliases: [azure activity log, who deleted azure resource, azure audit trail, azureactivity kql, azure diagnostic settings, azure log retention 90 days]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Azure Audit Logging (Activity Log & Diagnostic Settings)

Azure has three audit layers. Know which one answers your question before you start searching.

| Layer | Answers | Where | Default retention |
| :--- | :--- | :--- | :--- |
| **Activity Log** | Who created, changed or deleted a resource (control plane) | Per subscription; `AzureActivity` in Log Analytics | 90 days, then gone unless exported |
| **Entra ID logs** | Who signed in, who changed users, apps and roles | `SigninLogs`, `AuditLogs`, `AADServicePrincipalSignInLogs` | 7–30 days by license |
| **Resource logs** | What happened *inside* a resource (blob reads, Key Vault gets, firewall hits) | Per resource; off until you add a **diagnostic setting** | None until configured |

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Send everything to Log Analytics first

Without export, the Activity Log is lost after 90 days and resource logs are never kept. Do this before an incident.

```bash
# change: subscription Activity Log -> Log Analytics workspace
az monitor diagnostic-settings subscription create --name to-law \
  --location <region> --workspace <law-resource-id> \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"Alert","enabled":true},{"category":"ServiceHealth","enabled":true}]'

# What is already configured
az monitor diagnostic-settings subscription list -o table
az monitor diagnostic-settings list --resource <resource-id> -o table
```

At scale, deploy diagnostic settings with the built-in Azure Policy initiatives ("Enable allLogs category group resource logging...") rather than by hand ([Policy & governance](policy-governance.md)).

## 2. Query the Activity Log without a workspace

```bash
az monitor activity-log list --offset 7d --max-events 200 \
  --query "[].{time:eventTimestamp, caller:caller, op:operationName.value, status:status.value, resource:resourceId}" -o table

az monitor activity-log list --resource-group <rg> --offset 24h --status Failed -o table
az monitor activity-log list --caller attacker@contoso.com --offset 30d -o table
```

```powershell
Get-AzActivityLog -StartTime (Get-Date).AddDays(-7) -Caller 'user@contoso.com' |
  Select-Object EventTimestamp, OperationName, Status, ResourceId
```

## 3. Investigation queries (AzureActivity)

```kusto
// Everything one identity did, newest first
AzureActivity
| where TimeGenerated > ago(7d) and Caller =~ "user@contoso.com"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, _ResourceId, CallerIpAddress
| order by TimeGenerated desc
```

```kusto
// Who deleted resources
AzureActivity
| where OperationNameValue endswith "/DELETE" and ActivityStatusValue =~ "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
```

```kusto
// Callers acting from an IP they have not used in the last 30 days
let known = AzureActivity | where TimeGenerated between (ago(30d) .. ago(1d)) | distinct Caller, CallerIpAddress;
AzureActivity
| where TimeGenerated > ago(1d) and isnotempty(CallerIpAddress)
| join kind=leftanti known on Caller, CallerIpAddress
| summarize Ops = count(), Operations = make_set(OperationNameValue, 20) by Caller, CallerIpAddress
```

```kusto
// High-value operations
AzureActivity
| where OperationNameValue in~ (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.AUTHORIZATION/LOCKS/DELETE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId
```

`Caller` is a UPN for users and an **object ID (GUID)** for service principals and managed identities. Resolve it with `az ad sp show --id <guid>`.

## 4. Log tampering

Disabling logging is an attacker step ([T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/), formerly T1562.008). Alert on:

- `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE` or `/WRITE` by anyone outside the platform team.
- `MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE` or `.../TABLES/WRITE` (retention changes).
- Deleting a workspace's data export rules or a storage account that holds archived logs.

Activity Log entries themselves cannot be edited or deleted by tenant users.

## 5. Retention and archive

```bash
az monitor log-analytics workspace show -g <rg> -n <law> --query retentionInDays
# change: interactive retention for one table, plus long-term (total) retention
az monitor log-analytics workspace table update -g <rg> --workspace-name <law> -n AzureActivity \
  --retention-time 90 --total-retention-time 730
```

Keep at least one year of control-plane and identity logs. Most investigations start weeks after the first access.

## 6. Export for an investigation

```bash
az monitor log-analytics query -w <workspace-guid> \
  --analytics-query "AzureActivity | where TimeGenerated > ago(30d) and Caller =~ 'user@contoso.com'" \
  -o json > activity-user-$(date +%F).json
```

Record the query, time range and SHA-256 of the export with the evidence.

## Related

- [Monitoring & log queries](monitoring-logs.md)
- [Microsoft 365 → Entra ID sign-in logs](../microsoft-365/entra.md#sign-in-logs)
- [Microsoft 365 → Unified Audit Log](../microsoft-365/audit-log-investigation.md)
- [Persistence & threat hunting](persistence-hunting.md)

## Sources

- [Azure Activity Log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)
- [Diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)
- [Log Analytics data retention](https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-configure)
