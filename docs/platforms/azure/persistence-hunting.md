---
title: Azure Persistence & Threat Hunting
platforms: [Azure, Entra ID]
languages: [KQL, Bash, PowerShell]
tasks: [Threat Hunting, Incident Response, Investigation, Detection Engineering]
category: Persistence
tags: [azure, persistence, threat hunting, role assignment, app credentials, automation runbook, logic apps, run command, mitre attack]
aliases: [azure persistence techniques, hunt azure backdoor, attacker added service principal secret, azure automation runbook persistence, azure lateral movement, azure attack paths]
difficulty: advanced
verified: false
---

# Azure Persistence & Threat Hunting

An attacker with Azure control-plane access needs persistence that **survives a password reset**. That means identities and code the organization does not watch. Hunt each technique below in `AzureActivity` and the Entra ID `AuditLogs`. Each hunt assumes logs are exported ([Audit logging](audit-logging.md)).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Queries are hunting starting points: baseline your own environment before turning any into an alert.

## 1. Technique map

| Technique | ATT&CK | Where it shows |
| :--- | :--- | :--- |
| New role assignment to an attacker principal | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | `AzureActivity` roleAssignments/write |
| Secret or certificate added to an app / service principal | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | `AuditLogs` "Update application – Certificates and secrets management" |
| New user, guest or federated domain | [T1136.003](https://attack.mitre.org/techniques/T1136/003/), [T1484.002](https://attack.mitre.org/techniques/T1484/002/) | `AuditLogs` Add user / Set domain authentication |
| Automation runbook, Logic App or Function with a managed identity | [T1053](https://attack.mitre.org/techniques/T1053/), [T1648](https://attack.mitre.org/techniques/T1648/) | `AzureActivity` automationAccounts/runbooks/write, workflows/write, sites/write |
| VM Run Command / Custom Script Extension | [T1651](https://attack.mitre.org/techniques/T1651/) | `AzureActivity` runCommand/action, extensions/write |
| User-assigned identity attached to a resource the attacker controls | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | `AzureActivity` userAssignedIdentities/assign/action |
| Disabled logging | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | `AzureActivity` diagnosticSettings/delete |

## 2. Hunts

```kusto
// H1: role assignments made by someone who rarely makes them
let usual = AzureActivity
    | where TimeGenerated between (ago(60d) .. ago(7d))
    | where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
    | distinct Caller;
AzureActivity
| where TimeGenerated > ago(7d) and OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success" and Caller !in (usual)
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, Properties
```

```kusto
// H2: credentials added to applications or service principals
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName has_any ("Certificates and secrets management", "Add service principal credentials")
| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),
         Target = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, Actor, Target, Result
```

```kusto
// H3: new code that runs with an identity (automation, logic apps, functions)
AzureActivity
| where TimeGenerated > ago(30d) and ActivityStatusValue =~ "Success"
| where OperationNameValue in~ (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WEBHOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/WRITE",
    "MICROSOFT.LOGIC/WORKFLOWS/WRITE",
    "MICROSOFT.WEB/SITES/WRITE",
    "MICROSOFT.WEB/SITES/FUNCTIONS/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
```

```kusto
// H4: Run Command or extensions across many VMs in a short window (mass execution)
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue in~ ("MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
                                "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE")
| summarize VMs = dcount(_ResourceId), Ops = count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where VMs >= 3
```

```kusto
// H5: service principal sign-ins from new IPs (needs AADServicePrincipalSignInLogs)
let known = AADServicePrincipalSignInLogs
    | where TimeGenerated between (ago(30d) .. ago(1d)) | distinct AppId, IPAddress;
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1d) and ResultType == 0
| join kind=leftanti known on AppId, IPAddress
| project TimeGenerated, ServicePrincipalName, AppId, IPAddress, Location, ResourceDisplayName
```

```kusto
// H6: logging or locks removed
AzureActivity
| where OperationNameValue in~ ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE", "MICROSOFT.AUTHORIZATION/LOCKS/DELETE",
                                "MICROSOFT.OPERATIONALINSIGHTS/WORKSPACES/DELETE", "MICROSOFT.SECURITY/PRICINGS/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
```

## 3. Point-in-time sweep (no logs needed)

When logs are missing, inspect the current state:

```bash
# Apps with credentials added recently
az ad app list --all --query "[].{app:displayName, id:appId, secrets:passwordCredentials[].endDateTime, certs:keyCredentials[].endDateTime}" -o json

# Automation accounts and their runbooks
az automation account list -o table
az automation runbook list -g <rg> --automation-account-name <aa> --query "[].{name:name, state:state, modified:lastModifiedTime}" -o table

# Logic Apps and Function Apps with a managed identity
az resource list --resource-type Microsoft.Logic/workflows --query "[?identity].{name:name, rg:resourceGroup}" -o table
az functionapp list --query "[?identity].{name:name, rg:resourceGroup}" -o table
```

Then review [role assignments](identity-access.md#2-list-role-assignments) and [custom roles](identity-access.md#3-custom-roles) for anything you cannot explain.

## 4. Attack paths to check proactively

- **Contributor on an Automation Account** whose managed identity is Owner on the subscription is effectively Owner.
- **Virtual Machine Contributor** on a VM whose managed identity can read Key Vault equals Key Vault read.
- **Application Administrator** in Entra ID can add a secret to any app, including one with high Azure roles.

Defender CSPM attack-path analysis and open-source tools such as AzureHound map these chains ([Security posture](security-posture.md)).

## Related

- [Hunting cloud identity persistence](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md)
- [Cloud and ephemeral asset hunting](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md)
- [Hypothesis-driven hunting framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md)

## Sources

- [MITRE ATT&CK IaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
- [Microsoft Entra audit log activities](https://learn.microsoft.com/entra/identity/monitoring-health/reference-audit-activities)
- [Azure resource provider operations](https://learn.microsoft.com/azure/role-based-access-control/resource-provider-operations)
