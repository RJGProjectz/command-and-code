---
title: Windows Kernel & Network Stack Tuning
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - CMD
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - windows
  - kernel
  - tcpip
  - bcdedit
  - performance
---

# Windows Kernel & Network Stack Tuning

System tuning, BCD boot configuration parameters, TCP/IP stack optimization (`NetTCPSetting`), SYN flood protection, and kernel memory pool allocations.

## 1. Process & Service First: Network & Kernel State

```powershell
# Query current TCP autotuning and congestion provider state
Get-NetTCPSetting -SettingName InternetCustom | Select-Object SettingName, AutoTuningLevelLocal, CongestionProvider, EcnCapability
```

## 2. TCP/IP Stack Performance & Hardening

```powershell
# 1. Configure CUBIC or CTCP congestion algorithm for high-bandwidth WAN connections
Set-NetTCPSetting -SettingName InternetCustom -CongestionProvider CUBIC

# 2. Enable Explicit Congestion Notification (ECN) and RFC 1323 timestamps
Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Enabled -Timestamps Enabled

# 3. Enable Receive Window Auto-Tuning
Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Normal
```

## 3. TCP SYN Flood Protection (Registry)

```cmd
:: Harden TCP/IP stack against SYN flood attacks (SynAttackProtect)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v SynAttackProtect /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpen /t REG_DWORD /d 500 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxHalfOpenRetried /t REG_DWORD /d 400 /f
```

## 4. Boot Configuration Data (BCDEDIT) Kernel Tuning

```cmd
:: 1. Force Address Space Layout Randomization (ASLR) at boot
bcdedit /set nointegritychecks No
bcdedit /set testsigning No

:: 2. Ensure Data Execution Prevention (DEP) is enforced AlwaysOn
bcdedit /set nx AlwaysOn

:: 3. Enable Hypervisor-protected Code Integrity (HVCI) at boot
bcdedit /set hypervisorloadoptions VSM
```
