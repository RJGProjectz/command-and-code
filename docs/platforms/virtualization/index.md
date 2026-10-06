---
title: Virtualization
type: index
---

# Virtualization

Hypervisor commands for inventory, evidence preservation and containment.

!!! tip "IR principle for virtual machines"
    Before remediating a compromised VM, take a **memory-inclusive snapshot** (or saved state) and **disconnect its virtual NIC** instead of powering it off. You keep volatile evidence and stop the attacker in one step.

| Action | Hyper-V | VMware (PowerCLI) | Proxmox |
| --- | --- | --- | --- |
| List VMs | `Get-VM` | `Get-VM` | `qm list` |
| Snapshot with memory | `Save-VM` / Standard checkpoint | `New-Snapshot -Memory` | `qm snapshot ID NAME --vmstate 1` |
| Disconnect network | `Disconnect-VMNetworkAdapter` | `Set-NetworkAdapter -Connected:$false` | `qm set ID --netN ...,link_down=1` |

## All virtualization entries

<!-- cc:index platforms="Hyper-V|VMware|Proxmox" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Backup and Recovery Operations](../../tasks/administration/backup-and-recovery.md) | Workflow | Hyper-V, VMware, Proxmox, Windows Server, Linux | PowerShell, Bash | Administration, Forensics |
| [Hyper-V](hyper-v.md) | Entry | Hyper-V, Windows Server | PowerShell | Administration, Incident Response, Forensics |
| [Proxmox VE](proxmox.md) | Entry | Proxmox, Linux | Bash | Administration, Incident Response, Forensics |
| [VMware vSphere and ESXi](vmware.md) | Entry | VMware | PowerShell, Bash | Administration, Incident Response, Forensics |

<!-- /cc:index -->
