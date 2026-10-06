---
title: Hyper-V
platforms: [Hyper-V, Windows Server]
languages: [PowerShell]
tasks: [Administration, Incident Response, Forensics]
category: Virtualization
tags: [hyper-v, vm, checkpoint, isolation, save state]
aliases: [list vms, hyper-v snapshot, isolate vm, disconnect vm network, Get-VM]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Hyper-V

Requires the **Hyper-V** PowerShell module on the host (or RSAT).

## Inventory

```powershell
Get-VM | Select-Object Name, State, Uptime, Status, Generation, Version
Get-VMNetworkAdapter -VMName 'APP01' | Select-Object VMName, SwitchName, IPAddresses, MacAddress, Connected
Get-VMHardDiskDrive -VMName 'APP01' | Select-Object VMName, Path
```

`IPAddresses` is populated only when integration services are running in the guest.

## Preserve evidence: checkpoint and saved state

```powershell
Checkpoint-VM -Name 'APP01' -SnapshotName 'IR-2026-001-preserve'
Get-VMSnapshot -VMName 'APP01'
```

`Save-VM -Name 'APP01'` suspends the VM and writes its memory to disk — the memory state can be analysed later, unlike a hard power-off.

!!! warning "Production checkpoints exclude memory"
    The default *Production* checkpoint type uses VSS inside the guest and does **not** capture memory. For a memory-inclusive checkpoint, set `Set-VM -Name 'APP01' -CheckpointType Standard` first, or use `Save-VM`.

## Network-isolate a VM

```powershell
Disconnect-VMNetworkAdapter -VMName 'APP01'
```

Reconnect: `Connect-VMNetworkAdapter -VMName 'APP01' -SwitchName 'vSwitch-Prod'`.

## Power operations

```powershell
Stop-VM -Name 'APP01'              # guest shutdown via integration services
Stop-VM -Name 'APP01' -TurnOff     # hard power off — loses memory
Start-VM -Name 'APP01'
```

## Host logs

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Hyper-V-VMMS-Admin' -MaxEvents 50 | Select-Object TimeCreated, Id, Message
```

VM files: `.vmcx` (configuration), `.vmrs` (runtime state), `.vhdx` (disk), `.avhdx` (checkpoint differencing disk).

## Related

- [VMware](vmware.md)
- [Proxmox](proxmox.md)

## Sources

- [Hyper-V PowerShell module](https://learn.microsoft.com/powershell/module/hyper-v/)
- [Choose between standard or production checkpoints](https://learn.microsoft.com/windows-server/virtualization/hyper-v/manage/choose-between-standard-or-production-checkpoints-in-hyper-v)
