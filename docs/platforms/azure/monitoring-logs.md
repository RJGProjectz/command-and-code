---
title: Azure Monitor & Log Analytics Queries
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Investigation, Troubleshooting, Detection Engineering, Administration]
category: Logging
tags: [azure, azure monitor, log analytics, kql, metrics, alerts, azure monitor agent, data collection rules]
aliases: [run kql from cli, log analytics query powershell, azure monitor agent, data collection rule, azure metrics cli, azure alert rule]
difficulty: intermediate
verified: false
---

# Azure Monitor & Log Analytics Queries

Azure Monitor collects **metrics** (numbers every minute) and **logs** (records in a Log Analytics workspace, queried with KQL). Microsoft Sentinel runs on the same workspace, so a query that works here also works as a Sentinel analytics rule. See the [KQL section](../../detection/kql/index.md) for the language itself.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Find the workspaces

```bash
az monitor log-analytics workspace list \
  --query "[].{name:name, rg:resourceGroup, id:customerId, retention:retentionInDays, sku:sku.name}" -o table
```

`customerId` (a GUID) is the **workspace ID** used by query commands. The ARM resource ID is used by diagnostic settings.

## 2. Run KQL from the command line

```bash
az monitor log-analytics query -w <workspace-guid> \
  --analytics-query "Heartbeat | summarize LastSeen = max(TimeGenerated) by Computer | order by LastSeen asc" \
  -o table
```

```powershell
$r = Invoke-AzOperationalInsightsQuery -WorkspaceId <workspace-guid> -Query @'
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4625
| summarize Failures = count() by Account, IpAddress
| top 20 by Failures
'@
$r.Results | Format-Table
```

## 3. What tables do I have?

```kusto
search *
| where TimeGenerated > ago(1d)
| summarize Rows = count() by $table
| order by Rows desc
```

```kusto
// Cost view: GB ingested per table over 30 days
Usage
| where TimeGenerated > ago(30d) and IsBillable
| summarize GB = sum(Quantity) / 1000 by DataType
| order by GB desc
```

| Table | Source |
| :--- | :--- |
| `AzureActivity` | Subscription Activity Log ([Audit logging](audit-logging.md)) |
| `SigninLogs`, `AuditLogs` | Entra ID diagnostic setting |
| `SecurityEvent` | Windows Security log via Azure Monitor Agent (AMA) + data collection rule (DCR) |
| `Event` | Other Windows event logs via AMA |
| `Syslog` | Linux syslog via AMA |
| `Heartbeat` | Agent health, one row per minute per machine |
| `AzureDiagnostics` / resource-specific tables | Resource logs (Key Vault, Firewall, SQL, ...) |
| `SecurityAlert`, `SecurityIncident` | Defender for Cloud / Sentinel alerts |

## 4. Agents and data collection rules

The Log Analytics agent (MMA) was retired in August 2024. Use the **Azure Monitor Agent** with **data collection rules (DCRs)**, which decide which events each machine sends.

```bash
az vm extension list -g <rg> --vm-name <vm> --query "[?contains(name,'AzureMonitor')].{name:name, state:provisioningState}" -o table
az monitor data-collection rule list --query "[].{name:name, rg:resourceGroup}" -o table
az monitor data-collection rule association list --resource <vm-id> -o table
```

```kusto
// Machines that stopped sending (silent agents are a tampering and outage signal)
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer, OSType, Category
| where LastSeen < ago(30m)
| order by LastSeen asc
```

## 5. Metrics

```bash
az monitor metrics list-definitions --resource <vm-id> --query "[].name.value" -o tsv
az monitor metrics list --resource <vm-id> --metric "Percentage CPU" --interval PT5M --aggregation Average Maximum -o table
az monitor metrics list --resource <storage-id> --metric Egress --interval PT1H --aggregation Total -o table
```

A sudden jump in storage **Egress** or VM **Network Out Total** is a cheap exfiltration signal that needs no logging configuration.

## 6. Alerts (change)

```bash
# Log alert: Activity Log deletion of diagnostic settings
az monitor activity-log alert create -g <rg> -n alert-diag-delete \
  --condition category=Administrative and operationName=Microsoft.Insights/diagnosticSettings/delete \
  --action-group <action-group-id> --scope /subscriptions/<sub-id>

# Metric alert: CPU above 90% for 15 minutes
az monitor metrics alert create -g <rg> -n alert-cpu-<vm> --scopes <vm-id> \
  --condition "avg Percentage CPU > 90" --window-size 15m --evaluation-frequency 5m --action <action-group-id>

az monitor scheduled-query list -o table      # existing log search alerts
```

## 7. Query tips

- Always filter `TimeGenerated` first; it is the partition key and makes queries fast and cheap.
- Use `_ResourceId` to join across tables for the same resource.
- `project` early, `summarize` before `join`, and put the smaller table on the left of a `join`.
- Save tested queries as **functions** in the workspace so detections and dashboards share one definition.

## Related

- [KQL reference](../../detection/kql/index.md)
- [Audit logging](audit-logging.md)
- [Security posture & alerts](security-posture.md)
- [Centralized log forwarding](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md)

## Sources

- [Log Analytics overview](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview)
- [Azure Monitor Agent overview](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [az monitor log-analytics query](https://learn.microsoft.com/cli/azure/monitor/log-analytics)
