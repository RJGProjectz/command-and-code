---
title: Linux Storage, Partitioning & Logical Volume Management (LVM)
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - lvm
  - storage
  - partitioning
---

# Linux Storage, Partitioning & Logical Volume Management (LVM)

Procedures for inspecting block devices, resizing filesystems online, and managing Logical Volume Management (LVM) storage pools.

## 1. LVM Architecture Hierarchy

```text
[Physical Disks: /dev/sdb, /dev/sdc]
                 │
      [Physical Volumes (pvcreate)]
                 │
      [Volume Group: vg_data (vgcreate)]
                 │
      [Logical Volumes: lv_var, lv_home (lvcreate)]
                 │
      [Filesystems: XFS, ext4 (mkfs)]
```

## 2. Copy-Ready Operational Commands

```bash
# Block device inventory with mount points, UUIDs, and types
lsblk -f

# Create LVM storage hierarchy
pvcreate /dev/sdb
vgcreate vg_data /dev/sdb
lvcreate -n lv_app -L 50G vg_data
mkfs.xfs /dev/vg_data/lv_app

# Online expansion of Logical Volume and XFS filesystem
lvextend -L +20G /dev/vg_data/lv_app
xfs_growfs /mnt/app
```
