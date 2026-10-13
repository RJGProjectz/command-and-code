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
last_verified: 2026-10-12
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

## 2. Inspect (read-only)

```bash
# Block device inventory with mount points, UUIDs, and types
lsblk -f

# Space used per mounted filesystem, with type
df -hT

# LVM summary: physical volumes, volume groups, logical volumes
pvs
vgs
lvs -o +devices

# Mount table and fstab sanity check
findmnt
findmnt --verify
```

`vgs` shows free space in the `VFree` column; that is what `lvextend` can use without adding a disk.

## 3. Copy-Ready Operational Commands

All of these change the system. `pvcreate` and `mkfs` destroy any data on the target, so confirm the device name with `lsblk` first.

```bash
# Create LVM storage hierarchy
pvcreate /dev/sdb
vgcreate vg_data /dev/sdb
lvcreate -n lv_app -L 50G vg_data
mkfs.xfs /dev/vg_data/lv_app

# Mount it persistently by UUID (nofail: boot continues if the disk is missing)
mkdir -p /mnt/app
echo "UUID=$(blkid -s UUID -o value /dev/vg_data/lv_app) /mnt/app xfs defaults,nofail 0 0" >> /etc/fstab
mount -a

# Online expansion of Logical Volume and XFS filesystem
lvextend -L +20G /dev/vg_data/lv_app
xfs_growfs /mnt/app

# Same in one step for XFS or ext4 (-r resizes the filesystem too)
lvextend -r -L +20G /dev/vg_data/lv_app

# Add a new disk to an existing volume group
pvcreate /dev/sdc
vgextend vg_data /dev/sdc
```

On cloud VMs the disk itself is resized in the provider console first; then grow the partition (`growpart /dev/sda 3`, from `cloud-guest-utils` / `cloud-utils-growpart`) and the PV (`pvresize /dev/sda3`) before `lvextend`.

XFS can grow but **cannot shrink**. ext4 can shrink, but only unmounted (`resize2fs` before `lvreduce`), and only after a backup.

## 4. Snapshots for backup and forensics

An LVM snapshot freezes a point-in-time copy of a volume, which is useful before risky changes or to preserve evidence while the system keeps running.

```bash
# Snapshot with 10G of space for changes made after this moment
lvcreate -s -n lv_app_snap -L 10G /dev/vg_data/lv_app

# Mount read-only to inspect or copy (XFS needs nouuid because the UUID is duplicated)
mkdir -p /mnt/snap
mount -o ro,nouuid /dev/vg_data/lv_app_snap /mnt/snap

# Image it for forensics, then remove the snapshot
dd if=/dev/vg_data/lv_app_snap of=/evidence/lv_app.img bs=4M status=progress
umount /mnt/snap
lvremove /dev/vg_data/lv_app_snap
```

A snapshot that fills its space becomes invalid; watch `Data%` in `lvs`.

## Related

- [Disk Space Audit](../../tasks/administration/disk-space-audit.md)
- [Storage Partitioning and Mounting](../../tasks/administration/storage-partitioning-mounting.md)

## Sources

- [Red Hat — Configuring and managing logical volumes (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_and_managing_logical_volumes/index)
- [lvm(8)](https://man7.org/linux/man-pages/man8/lvm.8.html) · [lvextend(8)](https://man7.org/linux/man-pages/man8/lvextend.8.html) · [xfs_growfs(8)](https://man7.org/linux/man-pages/man8/xfs_growfs.8.html)
