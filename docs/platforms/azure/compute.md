---
title: Azure Virtual Machines (Compute)
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Investigation, Incident Response]
category: Compute
tags: [azure, virtual machines, run command, vm extensions, boot diagnostics, serial console, vmss]
aliases: [azure vm list, azure run command, azure vm extension persistence, azure serial console, azure vm boot diagnostics, start stop azure vm]
difficulty: intermediate
verified: false
---

# Azure Virtual Machines (Compute)

Azure VMs are ordinary Windows and Linux hosts, so the [Windows](../windows/index.md) and [Linux](../linux/index.md) sections apply inside the guest. This page covers the **control plane**: what the Azure API can see and do to a VM without logging in. That includes running code in the VM, which is why VM permissions matter.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Inventory

```bash
az vm list -d --query "[].{name:name, rg:resourceGroup, power:powerState, os:storageProfile.osDisk.osType, size:hardwareProfile.vmSize, privateIp:privateIps, publicIp:publicIps}" -o table
az vmss list -o table                                   # scale sets
az vm show -g <rg> -n <vm> --query "{id:vmId, identity:identity, zones:zones, nics:networkProfile.networkInterfaces[].id}"
```

```powershell
Get-AzVM -Status | Select-Object Name, ResourceGroupName, PowerState, @{n='OS';e={$_.StorageProfile.OsDisk.OsType}}
```

## 2. Power operations (change)

```bash
az vm start      -g <rg> -n <vm>
az vm stop       -g <rg> -n <vm>        # stops the OS but still bills compute
az vm deallocate -g <rg> -n <vm>        # releases compute; dynamic public IP is lost
az vm restart    -g <rg> -n <vm>
```

For incident response, **do not deallocate first**: memory is lost. Snapshot and isolate instead ([Incident response](incident-response.md)).

## 3. Run Command: code execution from the control plane

Run Command runs a script inside the guest as **SYSTEM** (Windows) or **root** (Linux) through the VM agent. It is a legitimate admin tool and a top attacker technique ([T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651/)).

```bash
# Windows guest (change: executes code)
az vm run-command invoke -g <rg> -n <vm> --command-id RunPowerShellScript \
  --scripts "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10"

# Linux guest (change: executes code)
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts "ss -tulpn; who"

# Managed Run Commands (newer, persisted as child resources); list them
az vm run-command list -g <rg> --vm-name <vm> -o table
```

Inside the guest, Run Command leaves artifacts:

| OS | Location |
| :--- | :--- |
| Windows | `C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\<ver>\Downloads\script*.ps1` and `C:\WindowsAzure\Logs\Plugins\` |
| Linux | `/var/lib/waagent/run-command/download/<n>/script.sh` and `/var/log/azure/run-command/handler.log` |

## 4. VM extensions

Extensions (Custom Script, DSC, monitoring agents) also run code at deploy time and on every reprovision. An unexpected Custom Script Extension is a persistence lead.

```bash
az vm extension list -g <rg> --vm-name <vm> --query "[].{name:name, type:typePropertiesType, publisher:publisher, state:provisioningState}" -o table
az vm extension show -g <rg> --vm-name <vm> -n <ext> --query settings      # protectedSettings are not returned
```

## 5. Detect Run Command and extension use

```kusto
AzureActivity
| where OperationNameValue in~ (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, _ResourceId
| order by TimeGenerated desc
```

## 6. Console access without the network

| Tool | Use | Command |
| :--- | :--- | :--- |
| Boot diagnostics screenshot | See a stuck boot or BSOD | `az vm boot-diagnostics get-boot-log -g <rg> -n <vm>` |
| Serial console | Interactive console when RDP/SSH is broken | `az serial-console connect -g <rg> -n <vm>` (extension `serial-console`) |
| Azure Bastion | RDP/SSH over TLS without a public IP | `az network bastion ssh --name <bastion> -g <rg> --target-resource-id <vm-id> --auth-type AAD` |
| Reset access (change) | Reset local admin password or SSH key | `az vm user update -g <rg> -n <vm> -u <user> -p <password>` |

Serial console and password reset are as powerful as Run Command; limit who holds `Virtual Machine Contributor`.

## 7. Disks and images

```bash
az disk list --query "[].{name:name, size:diskSizeGb, state:diskState, encryption:encryption.type, access:networkAccessPolicy}" -o table
az snapshot list -o table
az sig list -o table          # Compute galleries (shared images)
```

A disk with `networkAccessPolicy: AllowAll` can be exported with a SAS URL. Check for `Microsoft.Compute/disks/beginGetAccess/action` in the Activity Log as a data-exfiltration lead.

## 8. Instance metadata (inside the guest)

```bash
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | python3 -m json.tool
```

```powershell
Invoke-RestMethod -Headers @{Metadata='true'} -Uri 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
```

## Related

- [Networking](networking.md) — NSGs and effective rules
- [Incident response](incident-response.md) — snapshot and isolate a VM
- [Persistence & threat hunting](persistence-hunting.md)

## Sources

- [Run scripts with Run Command](https://learn.microsoft.com/azure/virtual-machines/run-command-overview)
- [VM extensions overview](https://learn.microsoft.com/azure/virtual-machines/extensions/overview)
- [Azure Serial Console](https://learn.microsoft.com/troubleshoot/azure/virtual-machines/serial-console-overview)
