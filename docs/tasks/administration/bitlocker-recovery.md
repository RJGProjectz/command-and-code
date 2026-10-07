---
title: Administration — BitLocker Key Retrieval & Status Audit
type: workflow
platforms:
  - Windows
  - Active Directory
languages:
  - PowerShell
  - CMD
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

---

## 1. PowerShell Local Encryption Status

```powershell
# Inspect BitLocker protection status across all fixed volumes
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus, KeyProtector
```

---

## 2. PowerShell Retrieve Recovery Key ID (Local Admin)

```powershell
$Volume = Get-BitLockerVolume -MountPoint "C:"
$RecoveryProtector = $Volume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
$RecoveryProtector.RecoveryPassword
```

---

## 3. PowerShell Query Recovery Password from Active Directory

```powershell
param([string]$ComputerName)

$CompObj = Get-ADComputer -Identity $ComputerName
Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" -SearchBase $CompObj.DistinguishedName -Properties msFVE-RecoveryPassword |
    Select-Object msFVE-RecoveryPassword
```

---

## 4. Windows CMD Operations (`manage-bde.exe`)

`manage-bde.exe` operates natively in standard Command Prompt, WinPE, and Windows RE recovery environments where PowerShell cmdlets are unavailable.

### Drive Encryption Status Audit

```bat
:: Display encryption status, percentage, and cipher algorithm across all drives
manage-bde -status

:: Query specific volume status
manage-bde -status C:
```

### Retrieve Recovery Key Protectors

```bat
:: Extract all configured key protectors on drive C: (TPM, Recovery Password, PIN)
manage-bde -protectors -get C:

:: Filter output directly for 48-digit numerical recovery password
manage-bde -protectors -get C: -type RecoveryPassword
```

### Unlocking & Managing Encrypted Drives in WinPE / Windows RE

```bat
:: Unlock a data volume using a 48-digit recovery password
manage-bde -unlock D: -RecoveryPassword 123456-123456-123456-123456-123456-123456-123456-123456

:: Unlock a volume using an external recovery key file (.bek)
manage-bde -unlock D: -RecoveryKey "F:\RecoveryKeys\key.bek"

:: Suspend BitLocker protection for one reboot (e.g. BIOS firmware flash)
manage-bde -protectors -disable C: -RebootCount 1

:: Re-enable BitLocker protection after maintenance
manage-bde -protectors -enable C:
```
