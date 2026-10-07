---
title: Storage Partitioning, Formatting and Filesystem Mounting
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - storage
  - disk
  - partition
  - formatting
  - mount
  - fstab
---

# Storage Partitioning, Formatting and Filesystem Mounting

End-to-end administration workflows for disk discovery, GPT initialization, filesystem formatting, mount point management, and persistent `/etc/fstab` configuration.

---

## 1. Windows Disk and Volume Management

### PowerShell Storage Module

```powershell
# Enumerate all physical disks attached to the system
Get-Disk | Select-Object Number, FriendlyName, OperationalStatus, Size, PartitionStyle

# Initialize a new raw disk with GPT partition style
Initialize-Disk -Number 1 -PartitionStyle GPT

# Create a new partition consuming maximum available space and assign drive letter
$Partition = New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter

# Format the new volume as NTFS with 64KB cluster allocation size
Format-Volume -DriveLetter $Partition.DriveLetter -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DataVolume"

# Verify volume mount and free space
Get-Volume -DriveLetter $Partition.DriveLetter
```

---

## 2. Linux Block Devices, Partitioning & Mounting

### Block Device Discovery

```bash
# List block devices with filesystem types, sizes, and UUIDs
lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS,UUID

# View raw disk geometry
sudo fdisk -l /dev/sdb
```

### Partitioning with `parted` & Formatting

```bash
# Create a GPT partition table on secondary disk /dev/sdb
sudo parted /dev/sdb --script mklabel gpt

# Create a primary partition spanning the full disk
sudo parted /dev/sdb --script mkpart primary ext4 0% 100%

# Format the partition with ext4 filesystem
sudo mkfs.ext4 -L "DataDrive" /dev/sdb1

# For high-throughput enterprise workloads, format with XFS:
# sudo mkfs.xfs -L "DataDrive" /dev/sdb1
```

### Persistent Mounting via `/etc/fstab`

```bash
# Create target mount point
sudo mkdir -p /mnt/datadrive

# Retrieve UUID of newly formatted partition
UUID=$(sudo blkid -s UUID -o value /dev/sdb1)
echo "Partition UUID: $UUID"

# Append mount configuration to /etc/fstab with safe defaults
echo "UUID=$UUID /mnt/datadrive ext4 defaults,noatime,nofail 0 2" | sudo tee -a /etc/fstab

# Test /etc/fstab without rebooting (mounts all unmounted entries)
sudo mount -a

# Verify active mount and filesystem utilization
df -hT /mnt/datadrive
```
