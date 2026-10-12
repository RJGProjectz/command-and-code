---
title: Azure Resource Hierarchy & Inventory
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Investigation, Assurance]
category: Inventory
tags: [azure, management groups, subscriptions, resource groups, resource graph, inventory, tags]
aliases: [azure resource graph query, list all azure resources, azure management group tree, azure inventory, what is in this subscription]
difficulty: basic
verified: false
---

# Azure Resource Hierarchy & Inventory

Before you investigate or harden anything, know what exists and where. Azure organizes resources in four levels. Policy and role assignments set at a level inherit downward, so the level an assignment sits at matters as much as the assignment.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Everything on this page is read-only except the tag commands marked **change**.

## 1. The hierarchy

| Level | Example | Notes |
| :--- | :--- | :--- |
| Tenant (Entra ID) | `contoso.onmicrosoft.com` | Identity boundary. Has one **root management group**. |
| Management group | `Root > Platform > Prod` | Up to six levels deep. Groups subscriptions for policy and RBAC. |
| Subscription | `sub-prod-001` | Billing and quota boundary; the most common RBAC scope. |
| Resource group | `rg-web-prod` | Lifecycle container. Deleting it deletes everything in it. |
| Resource | `vm-web-01` | ID format: `/subscriptions/<id>/resourceGroups/<rg>/providers/<namespace>/<type>/<name>` |

## 2. Walk the tree

```bash
az account management-group list --output table
az account management-group show --name <mg-name> --expand --recurse
az account list --all --query "[].{name:name, id:id, state:state, tenant:tenantId}" -o table
az group list --query "[].{name:name, location:location}" -o table
```

```powershell
Get-AzManagementGroup
Get-AzManagementGroup -GroupName <mg-name> -Expand -Recurse
Get-AzSubscription
Get-AzResourceGroup | Select-Object ResourceGroupName, Location, ProvisioningState
```

## 3. Inventory with Azure Resource Graph

Resource Graph queries every subscription you can read in one call, in KQL. It is the fastest inventory tool in Azure and works across thousands of subscriptions.

```bash
az extension add --name resource-graph      # once

# Count resources by type
az graph query -q "Resources | summarize count() by type | order by count_ desc" --first 50 -o table

# Every VM with its power state and OS
az graph query -q "
Resources
| where type == 'microsoft.compute/virtualmachines'
| project name, resourceGroup, subscriptionId, location,
          os = tostring(properties.storageProfile.osDisk.osType),
          power = tostring(properties.extended.instanceView.powerState.code)" -o table
```

```powershell
Install-Module Az.ResourceGraph -Scope CurrentUser
Search-AzGraph -Query "Resources | summarize count() by subscriptionId, type" -First 1000
```

### Useful Resource Graph queries

```kusto
// Public IP addresses and what they are attached to
Resources
| where type == "microsoft.network/publicipaddresses"
| project name, ip = tostring(properties.ipAddress),
          attachedTo = tostring(properties.ipConfiguration.id), resourceGroup, subscriptionId

// Resources created or changed in the last 24 hours (resource change history)
resourcechanges
| extend changeTime = todatetime(properties.changeAttributes.timestamp),
         changeType = tostring(properties.changeType),
         target = tostring(properties.targetResourceId)
| where changeTime > ago(1d)
| project changeTime, changeType, target
| order by changeTime desc

// Resources missing an owner tag
Resources
| where isnull(tags.owner) or tostring(tags.owner) == ""
| summarize count() by type
```

The `resourcechanges` table keeps about 14 days of change history and is a quick way to spot resources an attacker created. Confirm who made the change in the [Activity Log](audit-logging.md).

## 4. Resource providers

A provider (`Microsoft.Compute`, `Microsoft.Network`, ...) must be registered in a subscription before its resources can be created. An unexpected registration, such as `Microsoft.MachineLearningServices` or GPU-heavy compute in a subscription that never used it, can point to [resource hijacking](../../tasks/incident-response/azure-resource-hijacking.md).

```bash
az provider list --query "[?registrationState=='Registered'].namespace" -o tsv
```

## 5. Tags

```bash
az tag list --resource-id <resource-id>
az resource list --tag environment=prod -o table
az tag update --resource-id <resource-id> --operation Merge --tags owner=secops   # change
```

```powershell
Get-AzResource -TagName environment -TagValue prod
Update-AzTag -ResourceId <resource-id> -Tag @{ owner = 'secops' } -Operation Merge   # change
```

## 6. Export an inventory snapshot

```bash
az graph query -q "Resources | project id, name, type, location, resourceGroup, subscriptionId, tags" \
  --first 1000 -o json > azure-inventory-$(date +%F).json
```

Resource Graph returns at most 1,000 rows per page. For larger estates, page with `--skip-token`, or use `Search-AzGraph` in a loop.

## Related

- [Policy & governance](policy-governance.md)
- [Audit logging](audit-logging.md)
- [Security posture](security-posture.md)

## Sources

- [Azure Resource Graph overview](https://learn.microsoft.com/azure/governance/resource-graph/overview)
- [Management groups](https://learn.microsoft.com/azure/governance/management-groups/overview)
- [Resource Graph change analysis](https://learn.microsoft.com/azure/governance/resource-graph/how-to/get-resource-changes)
