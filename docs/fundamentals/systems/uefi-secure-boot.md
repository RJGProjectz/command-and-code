---
title: Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - uefi
  - secure-boot
  - tpm
  - bootkits
---

# Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics

Unified Extensible Firmware Interface (UEFI) and Secure Boot prevent rootkits and bootkits by validating the cryptographic signature of every bootloader component.

**Why it matters:** code that runs before the operating system (a bootkit) loads before antivirus and EDR, can hide from them, and survives reinstalling the OS. Secure Boot makes the firmware refuse unsigned or revoked boot code.

## 1. Boot Sequence Hierarchy

```text
[Power On] ──► [UEFI Firmware Initialized]
                      │
           (Verifies Signature against KEK / DB)
                      ▼
[Shim / Windows Boot Manager (bootmgfw.efi)]
                      │
           (Verifies Kernel Signature)
                      ▼
[OS Kernel (ntoskrnl.exe / vmlinuz)] ──► [Early Launch Anti-Malware (ELAM)] ──► [OS Drivers]
```

## 2. The Secure Boot key databases

| Variable | Holds | Changed by |
| --- | --- | --- |
| **PK** (Platform Key) | The one key that controls the KEK | Device manufacturer |
| **KEK** (Key Exchange Key) | Keys allowed to update `db` and `dbx` | Manufacturer, Microsoft |
| **db** (allowed) | Certificates and hashes of trusted boot code (Microsoft Windows CA, Microsoft UEFI CA for third-party loaders such as Linux `shim`) | Updates signed by a KEK |
| **dbx** (forbidden) | Hashes and certificates of revoked boot code | Updates signed by a KEK (Windows Update, `fwupd`) |

Linux distributions boot through Microsoft-signed `shim`, which checks GRUB and the kernel against the distribution's own key and any **MOK** (Machine Owner Key) enrolled with `mokutil`.

## 3. Hardware Root of Trust: TPM 2.0

Trusted Platform Module (TPM) measures boot integrity into Platform Configuration Registers (PCRs). If firmware or bootloader files are modified, PCR hashes change, preventing BitLocker key unsealing.

Secure Boot *enforces* (refuses bad code); measured boot with the TPM *records* (proves afterwards what ran). Use both.

## 4. Check the state

```powershell
# Windows: Secure Boot on? (requires admin; errors on legacy BIOS)
Confirm-SecureBootUEFI

# TPM present and ready
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled

# BitLocker protectors include the TPM
Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty KeyProtector
```

```bash
# Linux
mokutil --sb-state
ls /sys/firmware/efi >/dev/null 2>&1 && echo "UEFI boot" || echo "legacy BIOS boot"
```

`msinfo32` → *System Summary* also shows **BIOS Mode** and **Secure Boot State**.

## 5. Current issues to track

- **BlackLotus (CVE-2023-24932)**: a bootkit that bypasses Secure Boot by loading old, vulnerable but still-signed Windows boot managers. The fix requires revoking those boot managers in `dbx`, which Microsoft rolls out in stages; check the KB guidance before applying the revocations manually.
- **2011 certificate expiry**: Microsoft Corporation KEK CA 2011 and Microsoft UEFI CA 2011 expire in June 2026, and Microsoft Windows Production PCA 2011 in October 2026. Devices need the 2023 replacements, delivered through Windows Update and firmware updates, to keep receiving boot-component and `dbx` updates.
- Firmware updates are security updates; include them in patching.

## Related

- Concept: [Boot and startup sequence](../concepts/boot-startup-sequence.md)
- [BitLocker recovery](../../tasks/administration/bitlocker-recovery.md)
- [Windows system information](../../platforms/windows/system-information.md)

## Sources

- [Microsoft Learn — Secure the Windows boot process](https://learn.microsoft.com/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [Microsoft Support — KB5025885: managing the Windows Boot Manager revocations (CVE-2023-24932)](https://support.microsoft.com/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d)
- [Microsoft Support — Windows Secure Boot certificate expiration and CA updates](https://support.microsoft.com/topic/windows-secure-boot-certificate-expiration-and-ca-updates-7ff40d33-95dc-4c3c-8725-a9b95457578e)
- [UEFI Specification — Secure Boot and Driver Signing](https://uefi.org/specifications)
