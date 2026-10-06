---
title: Proxmox VE
platforms: [Proxmox, Linux]
languages: [Bash]
tasks: [Administration, Incident Response, Forensics]
category: Virtualization
tags: [proxmox, qm, pct, snapshot, kvm, lxc]
aliases: [qm list, proxmox snapshot with ram, isolate proxmox vm, pvesh]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Proxmox VE

Run on a Proxmox node as root. `qm` manages KVM virtual machines; `pct` manages LXC containers.

## Inventory

```bash
pveversion -v
qm list
pct list
qm config 101
pvesh get /cluster/resources --type vm
```

## Preserve evidence

```bash
qm snapshot 101 ir-2026-001 --vmstate 1 --description "Pre-remediation"
qm listsnapshot 101
```

`--vmstate 1` saves the VM's RAM with the snapshot.

## Network-isolate a VM

Set `link_down=1` on the interface, keeping its other settings. Check the current value first:

```bash
qm config 101 | grep ^net0
qm set 101 --net0 virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,link_down=1
```

Re-use the exact model, MAC and bridge from `qm config` so only the link state changes.

## Power operations

```bash
qm shutdown 101      # guest shutdown
qm stop 101          # hard stop — loses memory
qm start 101
```

## Logs and users

```bash
journalctl -u pvedaemon -u pveproxy --since today
tail -n 100 /var/log/pveproxy/access.log
pveum user list
```

Task logs are under `/var/log/pve/tasks/`.

## Related

- [Hyper-V](hyper-v.md)
- [VMware](vmware.md)

## Sources

- [qm(1)](https://pve.proxmox.com/pve-docs/qm.1.html)
- [pct(1)](https://pve.proxmox.com/pve-docs/pct.1.html)
- [pvesh(1)](https://pve.proxmox.com/pve-docs/pvesh.1.html)
