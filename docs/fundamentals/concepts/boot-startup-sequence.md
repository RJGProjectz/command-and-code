---
title: Boot and Startup Sequence (UEFI to Logon)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Threat Hunting, Troubleshooting]
category: Operating Systems
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-15
last_updated: 2026-10-15
tags: [concept, boot, uefi, bootmgr, winload, systemd, initramfs, autostart]
aliases: [boot process, Windows boot sequence, Linux boot sequence, bootmgfw.efi, winload.efi, initramfs, systemd targets, autostart locations, bootkit]
difficulty: basic
verified: true
last_verified: 2026-10-15
---

# Boot and Startup Sequence (UEFI to Logon)
> **Created**: 2026-10-15T03:20:00Z
> **Last Modified**: 2026-10-15T03:20:00Z
> **Author**: RJGProjectz

**In one line:** every stage of start-up loads and trusts the next one, so whatever an attacker plants earliest runs before — and can hide from — everything that comes after.

## What it is

| Stage | Windows (UEFI) | Linux (UEFI + systemd) |
| :--- | :--- | :--- |
| 1. Firmware | UEFI firmware: POST, then loads the boot application; Secure Boot checks its signature | same; Secure Boot usually loads `shim`, then GRUB or systemd-boot |
| 2. Boot manager | `\EFI\Microsoft\Boot\bootmgfw.efi` reads the BCD store | GRUB / systemd-boot reads its menu entries |
| 3. OS loader | `%SystemRoot%\System32\winload.efi` loads boot-start drivers and the kernel | boot loader loads the kernel image and the **initramfs** |
| 4. Kernel | `ntoskrnl.exe` loads the SYSTEM hive and `BOOT_START` drivers; an Early Launch Anti-Malware (ELAM) driver checks non-Microsoft boot drivers before they load | kernel unpacks the initramfs, finds and mounts the real root, switches to it |
| 5. First user-mode process | `smss.exe` (Session Manager) starts the remaining drivers and `csrss.exe`, `wininit.exe` | **systemd** as PID 1 |
| 6. Services | `wininit.exe` starts `services.exe` (SCM) and `lsass.exe`; SCM starts automatic [services](services-daemons.md) | systemd reaches `sysinit.target` → `basic.target` → `multi-user.target` (and `graphical.target`) |
| 7. Logon | `winlogon.exe` → LogonUI → LSA → `userinit.exe` → `explorer.exe` (Shell) | `getty`/`login`, sshd or a display manager → PAM → user's shell and `systemd --user` |
| 8. User autostart | Run/RunOnce keys, Startup folder, scheduled tasks at logon | shell profiles (`~/.bashrc`, `/etc/profile.d/`), XDG autostart, user units |

## How it works

```text
firmware ─► boot manager ─► OS loader ─► kernel + early drivers ─► smss / systemd (PID 1)
   │ Secure Boot verifies signatures here        │ Measured Boot records hashes in the TPM
   ▼                                              ▼
bootkits and malicious firmware modules          rootkit drivers / kernel modules
                    ─► services ─► logon ─► user autostarts
                         │            │           │
                 persistence as SYSTEM/root   Winlogon / PAM hooks   per-user Run keys, profiles
```

Each later stage is easier for an attacker to reach but also easier to see. Defenders inventory every stage: firmware
and Secure Boot state, boot configuration, drivers and kernel modules, services, logon hooks and user autostarts.
Details of Secure Boot keys and the TPM are on [UEFI and Secure Boot](../systems/uefi-secure-boot.md).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1542.003](https://attack.mitre.org/techniques/T1542/003/) Bootkit · [T1014](https://attack.mitre.org/techniques/T1014/) Rootkit · [T1547](https://attack.mitre.org/techniques/T1547/) Boot or Logon Autostart Execution · [T1547.004](https://attack.mitre.org/techniques/T1547/004/) Winlogon Helper DLL · [T1037](https://attack.mitre.org/techniques/T1037/) Boot or Logon Initialization Scripts · [T1543](https://attack.mitre.org/techniques/T1543/) Create or Modify System Process · [T1688](https://attack.mitre.org/techniques/T1688/) Safe Mode Boot |
| **What it leads to** | code that runs before the EDR, survives reinstalling the OS (firmware) or every reboot (services, autostarts) |
| **Where defenders meet it** | Secure Boot turned off, an unsigned driver or kernel module, an unknown entry in an autoruns listing, a host booting into Safe Mode unexpectedly |

## Do it

```bash
cc find "autostart" ; cc view docs/fundamentals/systems/uefi-secure-boot.md
```

```powershell
# Last boot time, Secure Boot state (admin, UEFI only) and the boot entries
(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
Confirm-SecureBootUEFI
bcdedit /enum
# Boot- and system-start drivers (Start 0 and 1)
Get-CimInstance -ClassName Win32_SystemDriver |
    Where-Object { $_.StartMode -in 'Boot', 'System' } |
    Select-Object -Property Name, StartMode, State, PathName
```

```bash
# Secure Boot state, time spent per stage, and the order systemd started units
mokutil --sb-state
systemd-analyze
systemd-analyze critical-chain
# Kernel modules loaded now
lsmod
```

## See it

| Source | What you see |
| :--- | :--- |
| System 6005 / 6006 / 6008 (EventLog) | event log started / stopped / previous shutdown was unexpected |
| System 1074 / 41 (Kernel-Power) | planned restart with process and user / reboot without a clean shutdown ([Windows event IDs](../../references/windows-event-ids.md)) |
| Measured Boot logs, Defender device health | firmware and boot components that changed |
| `journalctl -b`, `journalctl --list-boots` | everything logged during one Linux boot, and the list of boots |
| `dmesg` / kernel log | modules loaded, taint flags from unsigned or out-of-tree modules |

## Detect it

- Autostarts: [Windows Registry and Run keys](../../platforms/windows/registry.md) · [Windows scheduled tasks](../../platforms/windows/scheduled-tasks.md) · [Linux startup persistence](../../platforms/linux/persistence.md) · [Linux cron](../../platforms/linux/cron.md)
- Services: [Services and daemons](services-daemons.md) · [Suspicious service](../../tasks/investigation/suspicious-service.md)
- Hunt: [Scheduled task persistence review](../../tasks/threat-hunting/scheduled-task-persistence-review.md) · [Registry persistence](../../tasks/investigation/registry-persistence.md)
- Firmware and boot: [UEFI and Secure Boot](../systems/uefi-secure-boot.md) · Troubleshoot: [Windows troubleshooting](../../platforms/windows/troubleshooting.md) · [Linux troubleshooting](../../platforms/linux/troubleshooting.md)

## Related concepts

- [Windows registry](windows-registry.md) · [Processes, threads and handles](processes-threads.md) · [Malware types and analysis](malware-types-analysis.md)

## Sources

- Microsoft Learn: [Windows startup issues troubleshooting (boot phases)](https://learn.microsoft.com/troubleshoot/windows-client/performance/windows-boot-issues-troubleshooting) · [Secure the Windows boot process](https://learn.microsoft.com/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process) · [Run and RunOnce registry keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys) · [Confirm-SecureBootUEFI](https://learn.microsoft.com/powershell/module/secureboot/confirm-securebootuefi)
- MITRE ATT&CK: [T1547.004 Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547/004/)
- man7.org / systemd: [bootup(7)](https://man7.org/linux/man-pages/man7/bootup.7.html) · [systemd.special(7)](https://man7.org/linux/man-pages/man7/systemd.special.7.html) · [systemd-analyze(1)](https://man7.org/linux/man-pages/man1/systemd-analyze.1.html)
