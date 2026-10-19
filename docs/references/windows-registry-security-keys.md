---
title: Windows Registry Keys That Change Behaviour — Persistence and Security Settings
type: reference
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI, KQL, SPL]
tasks: [Investigation, Threat Hunting, Incident Response, Hardening, Forensics]
category: Reference
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-19
last_updated: 2026-10-19
tags: [windows, registry, persistence, autoruns, run keys, ifeo, winlogon, lsa, uac, defender exclusions, know normal]
aliases: [registry persistence locations, autostart registry keys, which registry keys to check, registry keys attackers change, ifeo debugger, appinit_dlls, lsa notification packages, wdigest uselogoncredential, localaccounttokenfilterpolicy, defender exclusions registry, safeboot service persistence, registry hardening values]
difficulty: intermediate
verified: true
last_verified: 2026-10-19
search:
  boost: 2
---

# Windows Registry Keys That Change Behaviour — Persistence and Security Settings
> **Created**: 2026-10-19T02:30:00Z
> **Last Modified**: 2026-10-19T02:30:00Z
> **Author**: RJGProjectz

An index **by purpose**: where code gets started, where security is switched off, and what the safe value is. Each
row says what to do when you find something: **remove** (delete the value), **reset** (put the default back — never
delete these keys) or **set** (hardening value). Collect before you change: export the key (`reg export`) and note the
last-write time. Background: [Windows registry concept](../fundamentals/concepts/windows-registry.md) ·
commands: [Registry and Run keys](../platforms/windows/registry.md).

!!! warning "Compare with a known-good build"
    Defaults differ by Windows version and installed software. Before you remove anything, compare against a clean
    machine of the same build, and check the file the value points at (path, signer, age).
    See [Windows process chains](windows-process-chains.md#signed-is-not-approved) for why "signed" is not enough.

## 1. Autostart and persistence

| Key → value | Starts | Normal | Action on a bad entry | ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| `HKLM` / `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` (and `WOW6432Node`) | program at logon | vendor agents, OneDrive, Teams, drivers' tray apps | **remove** the value | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` (also `HKCU`) | program at logon, set by policy | usually empty | **remove**; check which GPO set it | T1547.001 |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Userinit` | at sign-in | `C:\Windows\system32\userinit.exe,` | **reset** to the default | [T1547.004](https://attack.mitre.org/techniques/T1547/004/) |
| `...\Winlogon` → `Shell` (also `HKCU\...\Winlogon`) | user shell | `explorer.exe` (no `HKCU` value) | **reset** / remove the `HKCU` value | T1547.004 |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` → `BootExecute` | native program before Windows starts | `autocheck autochk *` | **reset** | T1547.001 |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>` → `ImagePath`, `Parameters\ServiceDll`, `FailureCommand` | service or driver | paths in `System32`, `Program Files` | stop, then `sc.exe delete <name>` for a rogue service; for a hijacked `ServiceDll` **reset** from a clean build | [T1543.003](https://attack.mitre.org/techniques/T1543/003/), [T1574.011](https://attack.mitre.org/techniques/T1574/011/) |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` → `Debugger` | another program instead of `<exe>` | rare (Process Explorer replacing Task Manager) | **remove** the `Debugger` value only — `MitigationOptions` (Exploit Protection) and `LSASS.exe` → `AuditLevel` (LSA protection audit) are legitimate, keep them | [T1546.012](https://attack.mitre.org/techniques/T1546/012/) |
| `IFEO\<exe>` → `GlobalFlag` `0x200` + `...\SilentProcessExit\<exe>` → `MonitorProcess` | program when `<exe>` exits | none | **remove** both | T1546.012 |
| `IFEO\sethc.exe`, `utilman.exe`, `osk.exe`, `narrator.exe` → `Debugger` | shell at the logon screen | none | **remove**; also check those files' hashes | [T1546.008](https://attack.mitre.org/techniques/T1546/008/) |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows` → `AppInit_DLLs`, `LoadAppInit_DLLs` | DLL in every process loading `user32.dll` | empty / `0`; ignored when Secure Boot is on | **set** `LoadAppInit_DLLs`=`0`, clear `AppInit_DLLs` | [T1546.010](https://attack.mitre.org/techniques/T1546/010/) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` | DLL in processes that call `CreateProcess` | key absent | **remove** the key | [T1546.009](https://attack.mitre.org/techniques/T1546/009/) |
| `HKLM\Software\Microsoft\Active Setup\Installed Components\<GUID>` → `StubPath` | program once per user at logon | Windows and Office components | **remove** an unknown GUID | [T1547.014](https://attack.mitre.org/techniques/T1547/014/) |
| `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` | DLL instead of the `HKLM` COM server | few per-user entries | **remove** the `HKCU` override | [T1546.015](https://attack.mitre.org/techniques/T1546/015/) |
| `HKLM\Software\Microsoft\Netsh` | DLL loaded by `netsh.exe` | Windows helper DLLs in `System32` | **remove** a non-Windows value | [T1546.007](https://attack.mitre.org/techniques/T1546/007/) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>` → `Driver` | DLL in `spoolsv.exe` (SYSTEM) | `localspl.dll`, `tcpmon.dll`, vendor monitors | **remove** an unknown monitor | [T1547.010](https://attack.mitre.org/techniques/T1547/010/) |
| `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<name>` → `DllName` | DLL in the time service | `NtpClient`, `NtpServer`, `VMICTimeProvider` | **remove** an unknown provider | [T1547.003](https://attack.mitre.org/techniques/T1547/003/) |
| `HKCU\Control Panel\Desktop` → `SCRNSAVE.EXE` | screensaver program | `.scr` in `System32` or absent | **reset** | [T1546.002](https://attack.mitre.org/techniques/T1546/002/) |
| `HKCU\Software\Microsoft\Office test\Special\Perf` (default value) | DLL when Office starts | key absent | **remove** the key | [T1137.002](https://attack.mitre.org/techniques/T1137/002/) |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<task>` → `SD` | hidden scheduled task when `SD` is deleted | every task has `SD` | rebuild or delete the task; investigate (Tarrask) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` / `Network\<name>` | service that also runs in Safe Mode | Windows services and drivers | **remove** a non-Windows entry (ransomware boots into Safe Mode to bypass EDR) | [T1688](https://attack.mitre.org/techniques/T1688/), formerly T1562.009 |

## 2. Credentials and LSA

| Key → value | Effect | Safe value | Action |
| :--- | :--- | :--- | :--- |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `Authentication Packages` | DLLs loaded into `lsass.exe` | `msv1_0` | **reset**; extra DLL = [T1547.002](https://attack.mitre.org/techniques/T1547/002/) |
| `...\Lsa` → `Security Packages` (and `Lsa\OSConfig`) | SSP DLLs loaded into `lsass.exe` | compare with a clean build | **reset**; extra DLL (e.g. `mimilib`) = [T1547.005](https://attack.mitre.org/techniques/T1547/005/) |
| `...\Lsa` → `Notification Packages` | password-filter DLLs that see cleartext password changes | `scecli` (plus vendor password-policy products you deployed) | **remove** unknown entries — [T1556.002](https://attack.mitre.org/techniques/T1556/002/) |
| `...\Lsa` → `RunAsPPL` | LSA protection (lsass as protected process) | `1` (UEFI-locked) or `2` (not locked, Windows 11 22H2+) | **set** |
| `...\Lsa` → `LmCompatibilityLevel` | NTLM versions sent and accepted | `5` (NTLMv2 only, refuse LM and NTLM) | **set** after an NTLM audit |
| `...\Lsa` → `NoLMHash` | stop storing LM hashes | `1` | **set** |
| `...\Lsa` → `DisableRestrictedAdmin` | RDP Restricted Admin (pass-the-hash into RDP when enabled) | absent or `1` unless you rely on it | review if set to `0` |
| `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential` | `1` keeps cleartext passwords in LSASS memory | `0` or absent | **set** `0`; `1` on a modern host is an attacker change ([T1112](https://attack.mitre.org/techniques/T1112/)) |
| `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` → `CachedLogonsCount` | cached domain logons (crackable offline) | `0`–`2` on servers, low on laptops | **set** |
| `HKLM\SAM`, `HKLM\SECURITY` | local hashes, LSA secrets | readable by SYSTEM only | alert on `reg save` of either ([T1003.002](https://attack.mitre.org/techniques/T1003/002/), [T1003.004](https://attack.mitre.org/techniques/T1003/004/)) |

## 3. Security controls switched off

| Key → value | Attacker sets | Safe value | Action |
| :--- | :--- | :--- | :--- |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` → `EnableLUA` | `0` (UAC off) | `1` | **set** |
| `...\Policies\System` → `ConsentPromptBehaviorAdmin` | `0` (elevate without prompt) | `2` (prompt on secure desktop) or the default `5` | **set** |
| `...\Policies\System` → `LocalAccountTokenFilterPolicy` | `1` (full admin token for remote local accounts) | `0` or absent | **set** `0`; `1` enables pass-the-hash with local admins |
| `HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions\Paths` / `Extensions` / `Processes` | folders or processes Defender skips | only exclusions you documented | **remove**; prefer `Get-MpPreference` to read effective exclusions ([T1685](https://attack.mitre.org/techniques/T1685/), formerly T1562.001) |
| `HKLM\Software\Policies\Microsoft\Windows Defender` → `DisableAntiSpyware`, `Real-Time Protection\DisableRealtimeMonitoring` | `1` | absent; turn on Tamper Protection (it ignores these changes) | **remove** |
| `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` → `EnableScriptBlockLogging` | `0` or key deleted | `1` | **set** by GPO |
| `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>` → `MaxSize`; `...\WINEVT\Channels\<channel>` → `Enabled` | tiny log size, channel disabled | sized to your retention; `1` | **reset** ([T1685.001](https://attack.mitre.org/techniques/T1685/001/), formerly T1562.002) |
| `HKLM\SYSTEM\CurrentControlSet\Services\<SysmonDrv / EDR driver>` → `Start` | `4` (disabled) | `0`–`2` as installed | **reset** and investigate ([T1685](https://attack.mitre.org/techniques/T1685/), formerly T1562.001) |
| `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<Profile>` → `EnableFirewall` | `0` | `1` | **set** ([T1686](https://attack.mitre.org/techniques/T1686/), formerly T1562.004) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` → `fDenyTSConnections` | `0` (RDP on) | `1` unless the host needs RDP | **set** |
| `...\Terminal Server\WinStations\RDP-Tcp` → `UserAuthentication` | `0` (no NLA) | `1` | **set** |
| `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient` → `EnableMulticast` | — | `0` (LLMNR off) | **set** |
| `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` → `RequireSecuritySignature` | `0` | `1` | **set** (or `Set-SmbServerConfiguration -RequireSecuritySignature $true`) |

Prefer Group Policy or Intune for every **set** row so a local change is put back at the next refresh. Baselines:
[Windows security baseline](../tasks/hardening/windows-security-baseline.md) · [CIS ASR](../tasks/hardening/windows-cis-attack-surface-reduction.md).

## Check it on a host

```powershell
# Read-only: values from this page that differ from the safe value
$checks = @(
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; Safe = @($null, 0) }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LocalAccountTokenFilterPolicy'; Safe = @($null, 0) }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Safe = @(1) }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Name = 'LoadAppInit_DLLs'; Safe = @($null, 0) }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; Safe = @(1, 2) }
)
foreach ($c in $checks) {
    $item = Get-ItemProperty -Path $c.Path -Name $c.Name -ErrorAction SilentlyContinue
    $value = if ($item) { $item.($c.Name) } else { $null }
    [pscustomobject]@{ Key = $c.Path; Value = $c.Name; Current = $value; OK = $value -in $c.Safe }
}

# Winlogon and LSA package lists to compare with a clean build
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object -Property Userinit, Shell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object -Property 'Authentication Packages', 'Security Packages', 'Notification Packages'

# IFEO entries with a Debugger value
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
    Where-Object { $_.GetValue('Debugger') } | ForEach-Object { [pscustomobject]@{ Exe = $_.PSChildName; Debugger = $_.GetValue('Debugger') } }
```

```cmd
:: Export before you change anything (evidence + rollback)
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" C:\IR\winlogon.reg /y
:: Sysinternals Autoruns: every autostart location, unsigned and non-Microsoft only, CSV
autorunsc64.exe -accepteula -a * -h -s -m -c > C:\IR\autoruns.csv
```

## Hunt it in the SIEM

```kql
// Defender XDR: writes to persistence and defence-evasion keys from this page
DeviceRegistryEvents
| where Timestamp > ago(7d) and ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\Winlogon", @"\Image File Execution Options", @"\SilentProcessExit",
    @"\Control\Lsa", @"\SecurityProviders\WDigest", @"\Windows Defender\Exclusions", @"\AppCertDlls", @"\Control\SafeBoot", @"\Print\Monitors")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
```

```spl
index=sysmon (EventCode=12 OR EventCode=13)
  (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Winlogon\\*" OR TargetObject="*\\Image File Execution Options\\*"
   OR TargetObject="*\\Control\\Lsa\\*" OR TargetObject="*\\WDigest\\UseLogonCredential" OR TargetObject="*\\Windows Defender\\Exclusions\\*"
   OR TargetObject="*\\Control\\SafeBoot\\*")
| stats count min(_time) as first by host, Image, TargetObject, Details
| convert ctime(first)
```

## Related

- Process side: [Windows process parent/child chains](windows-process-chains.md)
- Concept: [Windows registry](../fundamentals/concepts/windows-registry.md) · [Services and daemons](../fundamentals/concepts/services-daemons.md)
- Commands: [Registry and Run keys](../platforms/windows/registry.md) · [Services](../platforms/windows/services.md) · [Microsoft Defender Antivirus](../platforms/windows/defender.md)
- Investigate: [Registry persistence](../tasks/investigation/registry-persistence.md) · [Credential dumping](../fundamentals/concepts/credential-dumping.md)
- Detection: [KQL file and registry events](../detection/kql/file-registry-events.md) · [Sysmon](../fundamentals/systems/sysmon.md)

## Sources

- Microsoft Learn: [Run and RunOnce keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys) · [AppInit_DLLs and Secure Boot](https://learn.microsoft.com/windows/win32/dlls/secure-boot-and-appinit-dlls) · [Configure added LSA protection](https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) · [Password filters](https://learn.microsoft.com/windows/win32/secmgmt/password-filters) · [Network security: LAN Manager authentication level](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level) · [UAC settings and configuration](https://learn.microsoft.com/windows/security/application-security/application-control/user-account-control/settings-and-configuration) · [Tamper protection](https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) · [Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns)
- MITRE ATT&CK: [T1547 Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/) · [T1546 Event Triggered Execution](https://attack.mitre.org/techniques/T1546/) · [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) and the Defense Impairment tactic (formerly T1562 Impair Defenses)
- Microsoft Security blog: [Tarrask malware uses scheduled tasks for defense evasion](https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)
