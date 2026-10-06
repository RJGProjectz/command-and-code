---
title: Windows Registry and Run Keys
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Forensics, Threat Hunting]
category: Registry
tags: [registry, run keys, persistence, autoruns, winlogon, ifeo, startup folder]
aliases: [find registry run keys, autorun locations, startup programs, reg query, HKCU Run, persistence locations]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Windows Registry and Run Keys

## Read a key and its values

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' | Select-Object -ExpandProperty PSChildName
```

`Get-ItemProperty` also returns `PSPath`, `PSParentPath`, `PSChildName`, `PSDrive` and `PSProvider` — filter them out when listing values:

```powershell
(Get-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').GetValueNames() |
    ForEach-Object { [pscustomobject]@{ Name = $_; Value = (Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run').GetValue($_) } }
```

**Windows CLI:**

```text
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s
```

## Common autostart locations

| Location | Runs |
| --- | --- |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Every user logon |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Next logon, then deleted |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 32-bit view of the above |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` | That user's logon (no admin needed to write) |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | Policy-based Run |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` → `Userinit`, `Shell` | Logon; default `Userinit` is `C:\Windows\system32\userinit.exe,` and `Shell` is `explorer.exe` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` → `Debugger` | Instead of `<exe>` ([T1546.012](https://attack.mitre.org/techniques/T1546/012/)) |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | Boot / service start — see [Services](services.md) |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | User logon (folder, not registry) |
| `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` | Any user logon (folder) |

These map to [T1547.001 — Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/). For full coverage use Sysinternals **Autoruns** (`autorunsc.exe -a * -c -h -s`), which checks hundreds of locations.

## Dump all Run keys and startup folders

```powershell
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    $item = Get-Item -Path $key -ErrorAction SilentlyContinue
    if (-not $item) { continue }
    foreach ($name in $item.GetValueNames()) {
        [pscustomobject]@{ Key = $key; Name = $name; Command = $item.GetValue($name) }
    }
}
Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime
```

Reusable tool covering Run keys, services, tasks, startup folders and Winlogon: [`Get-PersistenceSnapshot.ps1`](../../toolbox/powershell.md#get-persistencesnapshot).

## Check other users' HKCU

`HKCU:` is only the current user. Loaded profiles of other users are under `HKEY_USERS\<SID>`:

```powershell
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
Get-ChildItem -Path HKU:\ |
    Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
    ForEach-Object { Get-ItemProperty -Path "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue }
```

Users who are not logged on have their hive in `C:\Users\<name>\NTUSER.DAT` — load it with `reg load HKU\Offline C:\Users\<USER>\NTUSER.DAT` (elevated), inspect, then `reg unload HKU\Offline`.

## What to look for

- Values pointing to `C:\Users\`, `C:\ProgramData\`, `%TEMP%`, `C:\Windows\Temp`
- `powershell.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wscript.exe` with arguments
- Encoded or very long command lines
- `Userinit`/`Shell` values with anything appended
- Any `Debugger` value under Image File Execution Options for accessibility binaries (`sethc.exe`, `utilman.exe`)

## Remove a malicious value

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Updater'
```

Export first: `reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" C:\Cases\run-hkcu.reg`.

## Collect hives for forensics

```text
reg save HKLM\SYSTEM   C:\Cases\SYSTEM.hiv
reg save HKLM\SOFTWARE C:\Cases\SOFTWARE.hiv
reg save HKLM\SAM      C:\Cases\SAM.hiv
```

Requires an elevated prompt. `SAM` and `SECURITY` contain credential material — protect the output.

## Related

- [Registry Persistence workflow](../../tasks/investigation/registry-persistence.md)
- [KQL: Run key modifications](../../detection/kql/file-registry-events.md#run-key-modifications)
- [Sigma: Run key persistence](../../detection/sigma/examples.md#run-key-persistence)

## Sources

- [Run and RunOnce registry keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns)
