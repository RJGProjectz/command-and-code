---
title: Windows Storage & Disk Management
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - CMD
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - windows
  - storage
  - disks
  - partitions
  - bitlocker
---

# Windows Storage & Disk Management

Physical disk enumeration, partition topologies, volume filesystems (NTFS, ReFS), Storage Spaces pools, and BitLocker volume encryption across Windows and Windows Server.

## 1. Process & Service First: Storage Subsystem

```powershell
# Verify Virtual Disk (vds) and Storage Management services
Get-Service -Name vds, smphost, defragsvc | Select-Object Name, Status, StartType

# Ensure Virtual Disk Service is running for partition resizing
Start-Service vds
```

## 2. Disk & Partition Discovery

```powershell
# 1. Enumerate physical disks (BusType, MediaType: SSD/NVMe/HDD, Size)
Get-Disk | Select-Object Number, FriendlyName, SerialNumber, BusType, MediaType, OperationalStatus, Size

# 2. Inspect partition styles (GPT vs MBR) and partition tables
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type, IsActive, IsBoot

# 3. Enumerate volumes, file systems, and free capacity
Get-Volume | Where-Object DriveType -eq 'Fixed' |
    Select-Object DriveLetter, FileSystemLabel, FileSystem,
                  @{N="TotalGB";E={[math]::Round($_.Size / 1GB, 2)}},
                  @{N="FreeGB";E={[math]::Round($_.SizeRemaining / 1GB, 2)}}
```

## 3. Storage Spaces & Pool Inspection

```powershell
# Enumerate storage pools, resilient virtual disks, and physical drive enclosures
Get-StoragePool -IsPrimordial $false | Select-Object FriendlyName, OperationalStatus, HealthStatus, AllocatedSize, Size
Get-VirtualDisk | Select-Object FriendlyName, ResiliencySettingName, NumberOfDataCopies, OperationalStatus, Size
```

## 4. Operational Maintenance & BitLocker Auditing

```powershell
# 1. Query BitLocker encryption status and protection methods across all volumes
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionMethod, LockStatus, ProtectionStatus

# 2. Extend partition to consume all contiguous unallocated space
Resize-Partition -DriveLetter D -Size (Get-PartitionSupportedSize -DriveLetter D).SizeMax

# 3. Trigger volume trim / defragmentation analysis
Optimize-Volume -DriveLetter C -Analyze -Verbose
```
