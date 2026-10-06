---
title: Administration — BitLocker Key Retrieval & Status Audit
type: workflow
platforms:
  - Windows
  - Active Directory
languages:
  - PowerShell
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - administration
  - bitlocker
  - encryption
  - recovery
---

# Administration — BitLocker Key Retrieval & Status Audit

Procedure to audit local drive encryption status, retrieve BitLocker recovery keys, and verify escrow in Active Directory or Entra ID.

## 1. Local Encryption Status

```powershell
# Inspect BitLocker protection status across all fixed volumes
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus, KeyProtector
```

## 2. Retrieve Recovery Key ID (Local Admin)

```powershell
$Volume = Get-BitLockerVolume -MountPoint "C:"
$RecoveryProtector = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
$RecoveryProtector.RecoveryPassword
```

## 3. Query Recovery Password from Active Directory

```powershell
param([string]$ComputerName)

$CompObj = Get-ADComputer -Identity $ComputerName
Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -SearchBase $CompObj.DistinguishedName -Properties msFVE-RecoveryPassword |
    Select-Object msFVE-RecoveryPassword
```
