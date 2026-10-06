---
title: Investigation Playbook — Azure Resource Hijacking
type: workflow
platforms:
  - Azure
  - Microsoft 365
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
  - azure
  - cryptojacking
  - incident-response
---

# Investigation Playbook — Azure Resource Hijacking

Standardized operational playbook to detect, scope, and eradicate unauthorized cloud resource provisioning, cryptojacking workloads, and rogue C2 nodes in Microsoft Azure.

---

## 1. Objective & Scope

- **What is being investigated**: Unauthorized virtual machine deployments (especially GPU/HPC SKUs) or serverless function spikes.
- **Why it matters**: Cloud resource hijacking (MITRE ATT&CK [T1496](https://attack.mitre.org/techniques/T1496/)) can rack up thousands of dollars in compute costs within hours and leave persistent attacker footholds.
- **Affected scope**: Azure Subscriptions, Resource Groups, and Management Groups.

---

## 2. Telemetry Queries

### Azure Activity Log — Rogue VM Creation

```kql
AzureActivity
| where OperationNameValue == "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE"
| where ActivityStatusValue == "Succeeded"
| extend VM_Size = tostring(parse_json(Properties).requestbody.properties.hardwareProfile.vmSize)
| project TimeGenerated, Caller, ResourceGroup, VM_Size, Location, SubscriptionId
| order by TimeGenerated desc
```

### Azure Metrics — Compute Spike Identification

```kql
// Pinpoint sustained 90%+ CPU spikes on newly deployed virtual machines
InsightsMetrics
| where Origin == "vm.azm.ms" and Name == "Percentage CPU"
| summarize AverageCPU = avg(Val) by ResourceId, bin(TimeGenerated, 1h)
| where AverageCPU > 90
```

---

## 3. Analysis & Triaging

| Expected Normal Baseline | Suspicious Indicators |
| :--- | :--- |
| Deployed via CI/CD pipelines (Terraform/Bicep) | Deployed via Azure Portal or Azure CLI from anomalous geographic IP |
| Standard general-purpose VM sizes (`Standard_D2s_v5`) | High-compute GPU/HPC series (`Standard_NC*`, `Standard_ND*`, `Standard_HB*`) |
| Deployed in approved corporate regions (`EastUS`, `WestUS`) | Deployed in previously unutilized distant regions |

---

## 4. Containment & Remediation Actions

1. **Immediate De-allocation**:
   ```powershell
   Stop-AzVM -ResourceGroupName "SuspiciousRG" -Name "RogueVM01" -Force
   ```
2. **Revoke Deployer Identity**:
   - Identify the `Caller` from the Azure Activity log.
   - If a User Account: Revoke all refresh tokens and reset credentials immediately.
   - If a Service Principal: Disable the Service Principal in Entra ID and delete newly created client secrets.
3. **Capture Disk Snapshot for Forensics**:
   ```powershell
   $VM = Get-AzVM -ResourceGroupName "SuspiciousRG" -Name "RogueVM01"
   $SnapshotConfig = New-AzSnapshotConfig -SourceResourceId $VM.StorageProfile.OsDisk.ManagedDisk.Id -Location $VM.Location -CreateOption Copy
   New-AzSnapshot -ResourceGroupName "ForensicsRG" -SnapshotName "RogueVM01_OSDisk_Snap" -Snapshot $SnapshotConfig
   ```
4. **Subscription Budget Caps & Quotas**: Implement Azure Policy to disallow non-compliant VM families across the tenant.
