---
title: Backup and Recovery Operations
type: workflow
platforms: [Hyper-V, VMware, Proxmox, Windows Server, Linux]
languages: [PowerShell, Bash]
tasks: [Administration, Forensics]
category: Operations
tags: [backups, snapshots, disaster recovery, vmware, hyper-v, proxmox, restic, veeam]
aliases: [check backup, verify snapshots, snapshot cleanup, dr test, restore vm, vm backup]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# Backup and Recovery Operations

> **Created**: 2026-10-06T18:45:00Z  
> **Last Modified**: 2026-10-06T18:45:00Z  
> **Author**: RJGProjectz  

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Backup operations and snapshot deletions interact directly with virtual machine disks.
> 1. Long-running VM snapshots degrade storage performance and must be committed/merged during off-peak hours.
> 2. Validate snapshot consolidation status before deleting virtual disks.
> 3. Periodically test cold restore procedures into an isolated sandbox network.

**Trigger:** Daily backup verification checklist, pre-change snapshot creation, stale snapshot audit, or disaster recovery drill.

**Goal:** Verify backup completion, manage virtual machine snapshot lifecycles, and audit recovery points across hypervisor platforms.

---

## 1. Virtual Machine Snapshot Management & Hygiene

Snapshots are **temporary recovery checkpoints**, not long-term backups. Stale snapshots degrade IOPS and consume datastore storage.

### VMware vSphere / ESXi (PowerCLI)

Identify stale snapshots older than 72 hours across all VMs:

```powershell
# Find snapshots older than 3 days
Get-VM | Get-Snapshot | Where-Object { $_.Created -lt (Get-Date).AddDays(-3) } |
    Select-Object @{N='VM';E={$_.VM.Name}}, Name, Created, SizeGB |
    Format-Table -AutoSize
```

Create a pre-maintenance snapshot:

```powershell
New-Snapshot -VM 'DB-SQL-01' -Name 'Pre-Patch-Checkpoint' -Description "Change Window $(Get-Date -Format 'yyyy-MM-dd')" -Quiesce
```

Delete (consolidate) a snapshot once changes are verified:

```powershell
Get-VM -Name 'DB-SQL-01' | Get-Snapshot -Name 'Pre-Patch-Checkpoint' | Remove-Snapshot -Confirm:$false
```

### Microsoft Hyper-V

List all checkpoints across Hyper-V hosts:

```powershell
Get-VMSnapshot -VMName * |
    Select-Object VMName, Name, CreationTime, SnapshotType |
    Sort-Object CreationTime
```

Remove a checkpoint to initiate automatic background AVHDX merge:

```powershell
Remove-VMSnapshot -VMName 'APP-SRV-01' -Name 'Pre-Update-Checkpoint'
```

### Proxmox VE (`pvesh` & `qm`)

List and verify VM snapshots via CLI:

```bash
# List snapshots for VM 100
qm listsnapshot 100

# Take a consistent snapshot with RAM state
qm snapshot 100 "Pre-Upgrade-$(date +%Y%m%d)" --description "Scheduled upgrade checkpoint"

# Delete snapshot after verification
qm delsnapshot 100 "Pre-Upgrade-$(date +%Y%m%d)"
```

---

## 2. Backup Job Verification

### Windows Server Backup (`WindowsServerBackup` Module)

Audit the result of the last backup run:

```powershell
# Get latest backup status
$LastBackup = Get-WBSummary
$LastBackup | Select-Object LastSuccessfulBackupTime, LastBackupResultHR, NextBackupTime

# Inspect detailed event history from event logs
Get-WinEvent -LogName 'Microsoft-Windows-Backup' -MaxEvents 10 |
    Select-Object TimeCreated, Id, Message
```

### Proxmox Backup Server / `vzdump` Verification

Inspect storage backup logs on Proxmox VE:

```bash
# Check recent backup tasks
pvesh get /cluster/tasks --typefilter vzdump --limit 10

# Verify vzdump backup archive integrity
vzdump 100 --dumpdir /var/lib/vz/dump --mode snapshot --compress zstd
```

---

## 3. Linux LVM Volume Snapshots

For bare-metal or self-managed Linux servers:

```bash
# Check available Volume Group extent space
vgs

# Create a 10GB LVM snapshot before software upgrade
sudo lvcreate --size 10G --snapshot --name root_snap /dev/vg0/root

# In case of upgrade failure, revert root volume on next reboot
# sudo lvconvert --merge /dev/vg0/root_snap
```

---

## Related

- [VMware vSphere and ESXi](../../platforms/virtualization/vmware.md)
- [Hyper-V Virtualization](../../platforms/virtualization/hyper-v.md)
- [Proxmox VE](../../platforms/virtualization/proxmox.md)
- [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md)
