---
title: Windows Services
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Administration, Hardening]
category: Services
tags: [services, persistence, sc.exe, 7045, unquoted service path]
aliases: [list services, service binary path, sc query, new service installed, service persistence]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Services

Services execute in the background with system startup, frequently under high privileges such as `LocalSystem` — making them high-value targets for persistence and privilege escalation ([T1543.003](https://attack.mitre.org/techniques/T1543/003/)). Follow the systematic 5-stage methodology: check active service and process states, inspect registry backing paths, validate configurations and permissions, audit installation events, and apply safe remediation controls.

## 1. Check Process, Service & Socket State

### List services with binary path and account

`Get-Service` in Windows PowerShell 5.1 does not show the binary path or account. Use CIM:

```powershell
Get-CimInstance -ClassName Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName, ProcessId |
    Sort-Object Name
```

PowerShell 7 adds `BinaryPathName`, `UserName` and `StartupType` to `Get-Service`.

**What to look for:**

- `PathName` pointing to writable staging directories: `C:\Users\`, `C:\ProgramData\`, `%TEMP%`, or `C:\Windows\Temp`
- `PathName` launching command shells or script hosts: `cmd.exe /c`, `powershell.exe`, `rundll32.exe`, or `mshta.exe`
- Masquerading service names imitating standard Windows components (`WindowsUpdateSvc`, `MicrosoftEdgeUpdater`)
- Automatic start services (`StartMode = Auto`) that are currently stopped

### Inspect one service

Query full service attributes, process identification, and runtime state:

```powershell
Get-CimInstance Win32_Service -Filter "Name = 'Spooler'" | Format-List *
```

**Windows CLI (sc.exe):**

```text
sc.exe query Spooler
sc.exe query state= all
```

!!! warning "`sc` is not `sc.exe` in PowerShell"
    In Windows PowerShell 5.1, `sc` is an alias for `Set-Content`. Always type `sc.exe`. Note the space after `state=` — it is required by the Windows binary parser.

## 2. Known Locations & Registry Storage

Windows stores all service definitions in the System registry hive. An adversary can hijack an existing legitimate service by modifying its `ImagePath` or `ServiceDll` instead of creating a new service record:

### Registry location

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
    ImagePath              Binary executable and launch arguments
    Start                  2 = Automatic, 3 = Manual, 4 = Disabled
    ObjectName             Account security context the service runs as
    Parameters\ServiceDll  Target DLL for svchost-hosted services
```

| Component | Registry / Filesystem Path | Purpose |
| :--- | :--- | :--- |
| **Service Root** | `HKLM\SYSTEM\CurrentControlSet\Services\<Name>` | Master registration key |
| **Executable** | Value `ImagePath` (e.g. `%SystemRoot%\System32\spoolsv.exe`) | Binary path invoked by SCM |
| **Hosted DLL** | Subkey `Parameters` → Value `ServiceDll` | DLL loaded by `svchost.exe -k` |
| **Log Target** | `System` event log (`EventLog-System`) | SCM service lifecycle events |

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Spooler' |
    Select-Object ImagePath, Start, ObjectName
```

## 3. Configuration Inspection & Vulnerability Checking

### Inspect service configuration and security descriptors

```text
sc.exe qc Spooler                 # configuration (binary, start type, dependencies)
sc.exe sdshow Spooler             # security descriptor in SDDL format
```

### Find unquoted service paths

An unquoted path containing spaces allows an attacker who can write to a parent directory to plant a malicious executable, gaining privilege escalation when the service restarts ([T1574.009](https://attack.mitre.org/techniques/T1574/009/)):

```powershell
Get-CimInstance Win32_Service |
    Where-Object { $_.PathName -and $_.PathName -notlike '"*' -and $_.PathName -match '^[^"]*\s[^"]*\.exe' } |
    Select-Object Name, StartMode, StartName, PathName
```

Each result is only exploitable if a parent folder in the path is writable by standard users — verify folder ACLs using [`icacls`](files-directories.md#check-file-and-folder-permissions).

## 4. Operational Diagnostics & Event Auditing

### Find recently installed services

Monitor and triage newly created services via the System event log:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045 } -MaxEvents 50 |
    Select-Object TimeCreated, @{ Name = 'Service'; Expression = { $_.Properties[0].Value } },
                               @{ Name = 'ImagePath'; Expression = { $_.Properties[1].Value } },
                               @{ Name = 'Account'; Expression = { $_.Properties[4].Value } }
```

| Event ID | Log Channel | Meaning |
| :--- | :--- | :--- |
| **7045** | System | A service was installed (logged by default on all Windows systems) |
| **4697** | Security | A service was installed (requires *Audit Security System Extension*) |
| **7040** | System | Service start type was altered |
| **7036** | System | Service transitioned into running or stopped state |

## 5. Hardening & Safe Service Lifecycle

### Stop and disable a service

Before stopping or removing an unauthorized service, preserve forensic evidence (copy the executable binary and export the registry key):

```powershell
# Stop and disable without rebooting
Stop-Service -Name 'BadSvc' -Force
Set-Service -Name 'BadSvc' -StartupType Disabled
```

To remove after evidence collection: `sc.exe delete BadSvc`. On PowerShell 7, `Remove-Service` is also available.

## Related

- [Suspicious Service workflow](../../tasks/investigation/suspicious-service.md)
- [Linux services (systemd)](../linux/systemd.md)
- [SPL: new service installs](../../detection/spl/windows-events.md#new-service-installed-7045)
- [Sigma: service installation](../../detection/sigma/examples.md#suspicious-service-installation)

## Sources

- [Win32_Service class](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service)
- [sc.exe query](https://learn.microsoft.com/windows-server/administration/windows-commands/sc-query)
- [Event 4697](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)
