---
title: VMware vSphere and ESXi
platforms: [VMware]
languages: [PowerShell, Bash]
tasks: [Administration, Incident Response, Forensics]
category: Virtualization
tags: [vmware, esxi, vcenter, powercli, esxcli, snapshot, ransomware]
aliases: [powercli, esxcli, vm snapshot with memory, esxi logs, disconnect vm nic]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# VMware vSphere and ESXi

## PowerCLI

Broadcom publishes PowerCLI as **VCF.PowerCLI** (version 9 onward); earlier releases are **VMware.PowerCLI**. Cmdlet names are unchanged.

```powershell
Connect-VIServer -Server vcsa01.contoso.local
Get-VM | Select-Object Name, PowerState, NumCpu, MemoryGB, VMHost | Sort-Object Name
Get-VM -Name 'APP01' | Get-NetworkAdapter | Select-Object Name, NetworkName, MacAddress, ConnectionState
```

### Preserve evidence

```powershell
New-Snapshot -VM 'APP01' -Name 'IR-2026-001' -Description 'Pre-remediation' -Memory
Get-Snapshot -VM 'APP01' | Select-Object Name, Created, SizeGB
```

`-Memory` includes RAM in the snapshot (`.vmsn`/`.vmem`), which can be analysed with memory-forensics tools.

### Network-isolate a VM

```powershell
Get-VM -Name 'APP01' | Get-NetworkAdapter | Set-NetworkAdapter -Connected:$false -Confirm:$false
```

### Recent events

```powershell
Get-VIEvent -Entity (Get-VM -Name 'APP01') -MaxSamples 100 | Select-Object CreatedTime, UserName, FullFormattedMessage
```

## ESXi shell (esxcli)

```bash
esxcli system version get
esxcli network ip connection list
esxcli software vib list
vim-cmd vmsvc/getallvms
esxcli system account list
```

| Log | Path |
| --- | --- |
| Host agent | `/var/log/hostd.log` |
| Authentication | `/var/log/auth.log` |
| Shell commands | `/var/log/shell.log` |
| vCenter agent | `/var/log/vpxa.log` |

**Security relevance:** ESXi hosts are a primary ransomware target — attackers enable SSH, stop VMs with `esxcli vm process kill` or `vim-cmd`, then encrypt datastores. Unexpected SSH enablement, new local accounts, and unsigned VIBs (`esxcli software vib list` acceptance level `CommunitySupported`) are high-priority findings.

## Related

- [Hyper-V](hyper-v.md)
- [Proxmox](proxmox.md)

## Sources

- [PowerCLI documentation](https://developer.broadcom.com/powercli)
- [esxcli command reference](https://developer.broadcom.com/xapis/esxcli-command-reference/latest/)
