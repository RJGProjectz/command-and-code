---
title: Windows Process Parent/Child Chains — Know Normal
type: reference
platforms: [Windows, Windows Server]
languages: [PowerShell, KQL, SPL]
tasks: [Investigation, Threat Hunting, Incident Response, Detection Engineering]
category: Reference
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-10-19
last_updated: 2026-10-19
tags: [windows, processes, process tree, parent child, lolbins, know normal, signed binaries, wdac, applocker]
aliases: [normal windows parent process, svchost parent, lsass parent, expected parent process, suspicious child process, office spawning powershell, wmiprvse child process, signed but malicious binary, lolbin parent child, hunt evil process tree]
difficulty: intermediate
verified: true
last_verified: 2026-10-19
search:
  boost: 2
---

# Windows Process Parent/Child Chains — Know Normal
> **Created**: 2026-10-19T02:10:00Z
> **Last Modified**: 2026-10-19T02:10:00Z
> **Author**: RJGProjectz

Most process detections are one of three questions: **is this the right parent, the right path and the right count?**
One card per process below. "Suspicious children" are a reason to look, not proof — confirm with the command line,
user, signer and what happened next. Short background: [Windows process architecture](../fundamentals/systems/windows-processes.md).

!!! note "Orphans are normal for boot processes"
    `smss.exe` starts a copy of itself per session; that copy starts `csrss.exe` and `wininit.exe` / `winlogon.exe` and
    then exits. Their parent PID therefore points at a process that no longer exists (or a reused PID). The same goes for
    `explorer.exe`, whose parent `userinit.exe` exits after logon.

## Boot and session processes

| Process | Normal parent | Path | Instances | Normal children | Suspicious |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `System` (PID 4) | none | kernel (`ntoskrnl.exe`) | 1 | `smss.exe`, `Registry`, `Memory Compression`, `Secure System` (VBS) | any user-mode child other than these |
| `smss.exe` | `System` | `%SystemRoot%\System32` | 1 master (session copies exit) | `autochk.exe`, per-session `smss.exe` copies | a long-lived second copy; any other parent |
| `csrss.exe` | `smss.exe` copy (exited) | `%SystemRoot%\System32` | 1 per session (0, 1, …) | rarely any | wrong path; a child shell; command line without `ObjectDirectory=\Windows` |
| `wininit.exe` | `smss.exe` copy (exited) | `%SystemRoot%\System32` | 1 (session 0) | `services.exe`, `lsass.exe`, `LsaIso.exe` (Credential Guard), `fontdrvhost.exe` | more than one; running outside session 0 |
| `winlogon.exe` | `smss.exe` copy (exited) | `%SystemRoot%\System32` | 1 per interactive session | `LogonUI.exe`, `userinit.exe`, `dwm.exe`, `fontdrvhost.exe` | `cmd.exe` / `powershell.exe` children; `Shell` / `Userinit` changed in the registry |
| `userinit.exe` | `winlogon.exe` | `%SystemRoot%\System32` | short-lived, exits | `explorer.exe` (or the configured shell) | still running after logon; anything other than the shell |
| `explorer.exe` | `userinit.exe` (exited) | `%SystemRoot%` | 1 per signed-in user (more with "separate process" folders) | whatever the user starts, Run-key programs | path not `C:\Windows`; parent still alive and not `userinit.exe`; running with no user signed in |

## Service and security processes

| Process | Normal parent | Path | Normal children | Suspicious |
| :--- | :--- | :--- | :--- | :--- |
| `services.exe` | `wininit.exe` | `%SystemRoot%\System32` | `svchost.exe`, own-process services (`spoolsv.exe`, `MsMpEng.exe`, vendor agents), `msiexec.exe /V` | `cmd.exe` / `powershell.exe` as a direct child (a service whose `ImagePath` is a command: PsExec-style and Impacket remote execution, Event 7045) |
| `lsass.exe` | `wininit.exe` | `%SystemRoot%\System32` | none in normal operation | any child; a second `lsass.exe`; any process opening it for memory read (Sysmon 10, [credential dumping](../fundamentals/concepts/credential-dumping.md)) |
| `svchost.exe` | `services.exe` | `%SystemRoot%\System32` (`SysWOW64` for 32-bit) | depends on the hosted service — see next table | no `-k <group>` argument; any parent other than `services.exe`; wrong path or look-alike name (`scvhost.exe`) |
| `spoolsv.exe` | `services.exe` | `%SystemRoot%\System32` | printer driver helpers | `cmd.exe`, `powershell.exe`, `rundll32.exe` (PrintNightmare-style driver loading) |
| `MsMpEng.exe` | `services.exe` | `%ProgramData%\Microsoft\Windows Defender\Platform\<version>` | `MpCmdRun.exe` | stopped, or exclusions added just before an incident |
| `msiexec.exe` | `services.exe` (the `/V` service instance) or the user's process (`/i`) | `%SystemRoot%\System32` | other `msiexec.exe` (custom actions) | `/i` or `/q` with an `http(s)://` package; children `cmd.exe` / `powershell.exe` from a package nobody deployed |

### `svchost.exe` children by hosted service

`svchost.exe` is a host. Read its command line (`-k <group> -p -s <service>`) to know which service you are looking at.

| Host (`-k` / `-s`) | Normal children | Suspicious children → likely technique |
| :--- | :--- | :--- |
| `DcomLaunch` | `WmiPrvSE.exe`, `dllhost.exe /Processid:{CLSID}`, `RuntimeBroker.exe`, `wsmprovhost.exe` (PowerShell remoting), UWP apps | `mmc.exe`, `excel.exe` started with no user action → DCOM lateral movement ([T1021.003](https://attack.mitre.org/techniques/T1021/003/)); `wsmprovhost.exe` → `cmd.exe` from an unexpected source host ([T1021.006](https://attack.mitre.org/techniques/T1021/006/)) |
| `netsvcs -s Schedule` | task actions: `taskhostw.exe`, programs in scheduled tasks | `cmd.exe`, `powershell.exe`, `rundll32.exe` from a task created recently → [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| `iissvcs -s WAS` (IIS) | `w3wp.exe` (one per application pool) | `w3wp.exe` → `cmd.exe`, `powershell.exe`, `whoami.exe` → web shell ([T1505.003](https://attack.mitre.org/techniques/T1505/003/)) |

## Hosts that run other code

| Process | Normal parent | Normal use | Suspicious |
| :--- | :--- | :--- | :--- |
| `WmiPrvSE.exe` | `svchost.exe -k DcomLaunch` | WMI providers (`%SystemRoot%\System32\wbem`) | children `cmd.exe` / `powershell.exe` → remote `Win32_Process.Create` ([T1047](https://attack.mitre.org/techniques/T1047/)) |
| `dllhost.exe` | `svchost.exe -k DcomLaunch` | COM surrogate, always `/Processid:{CLSID}` | no command-line arguments (common injection target); network connections |
| `rundll32.exe` | `explorer.exe`, `control.exe`, `svchost.exe` | `<dll>,<entry point>` arguments | no arguments; `comsvcs.dll,MiniDump` (LSASS dump); `javascript:`; a DLL in `%TEMP%` / `%APPDATA%` ([T1218.011](https://attack.mitre.org/techniques/T1218/011/)) |
| `regsvr32.exe` | installers, `msiexec.exe` | registering a local DLL | `/i:http…` or `scrobj.dll` ("Squiblydoo", [T1218.010](https://attack.mitre.org/techniques/T1218/010/)); parent Office or a script host |
| `mshta.exe` | rarely legitimate today | legacy `.hta` tools | any URL argument; parent Office, browser or `explorer.exe` opening a downloaded `.hta` ([T1218.005](https://attack.mitre.org/techniques/T1218/005/)) |
| `wscript.exe` / `cscript.exe` | `explorer.exe`, logon scripts | admin `.vbs` / `.js` | script in `Downloads`, `%TEMP%` or an archive; parent Office or Outlook |
| `powershell.exe` / `pwsh.exe` | `explorer.exe`, Windows Terminal, management agents | admin work | `-enc`, `-w hidden`, `-nop` together; parent Office, `mshta.exe`, `WmiPrvSE.exe`, `w3wp.exe`, `sqlservr.exe` |
| `cmd.exe` | `explorer.exe`, Windows Terminal, installers | admin work, batch files | parent `sqlservr.exe` (`xp_cmdshell`), `w3wp.exe`, `spoolsv.exe`, `lsass.exe`, `winlogon.exe` |
| `conhost.exe` | the console program it serves | console window host | parent is not a console program; running with no console parent |

## User applications

| Process | Normal parent | Normal children | Suspicious children |
| :--- | :--- | :--- | :--- |
| `WINWORD.EXE`, `EXCEL.EXE`, `POWERPNT.EXE`, `ONENOTE.EXE`, `MSACCESS.EXE` | `explorer.exe`, `OUTLOOK.EXE` (attachments) | `splwow64.exe` (printing), Office helpers | `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe` |
| `OUTLOOK.EXE` | `explorer.exe` | Office apps opening attachments, browser | any script host or shell (also Outlook rules/forms abuse) |
| `msedge.exe`, `chrome.exe`, `firefox.exe` | `explorer.exe` (or another app opening a link) | copies of itself (`--type=renderer`, `gpu-process`, `utility`), crash handler | `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe` |
| `AcroRd32.exe` / `Acrobat.exe` | `explorer.exe`, browser, Outlook | own helpers | any shell or script host |

Microsoft Defender ASR rules enforce several of these lines: **Block all Office applications from creating child processes**
(`d4f940ab-401b-4efc-aadc-ad5f3c50688a`), **Block Office communication application from creating child processes**
(`26190899-1602-49e8-8b27-eb1d0a1ce869`), **Block Adobe Reader from creating child processes** (`7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c`),
**Block process creations originating from PSExec and WMI commands** (`d1e49aac-8f56-4280-b9ba-993a6d77406c`) and
**Block use of copied or impersonated system tools** (`c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb`). The Office rules apply only
when Office is installed under `%ProgramFiles%`. Rollout: [ASR hardening](../tasks/hardening/windows-cis-attack-surface-reduction.md).

## Signed is not approved

A valid Microsoft signature tells you **who built** a file, not that your organization wants it to run. Attackers prefer
signed Windows binaries (LOLBins) because default allow-lists trust them.

| Check | What it tells you | What it does not |
| :--- | :--- | :--- |
| **Authenticode (embedded)** | the signature is inside the file; signer and timestamp | whether the file belongs on this host |
| **Catalog-signed** | most in-box Windows files are signed through a `.cat` file in `%SystemRoot%\System32\CatRoot`, so the file itself shows "not signed" in Explorer's properties | a copy moved outside `System32` is still the same signed file |
| **AppLocker default rules** | allow everything under `%WINDIR%` and `%PROGRAMFILES%` | every LOLBin in `System32` is allowed — add deny rules |
| **App Control for Business (WDAC)** | policy decides by signer, hash or path; Microsoft publishes a **recommended block list** | the block list is not on by default; you merge it into your policy |

Microsoft's recommended block list includes, among others, `mshta.exe`, `msbuild.exe`, `wmic.exe`, `cscript.exe`,
`wscript.exe`, `infdefaultinstall.exe`, `cdb.exe` / `windbg.exe` / `ntsd.exe` / `kd.exe`, `csi.exe` / `rcsi.exe`,
`Microsoft.Workflow.Compiler.exe`, `bash.exe` / `wsl.exe` and `dotnet.exe`. Not on that list but often abused:
`rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe` — watch their arguments and parents instead.
Policy guidance: [AppLocker](../fundamentals/systems/applocker.md) · [WDAC and Exploit Protection](../platforms/windows/wdac-exploit-guard.md) · [AppLocker rollout](../tasks/hardening/applocker-deployment-rollout.md).

```powershell
# Signer, signature type (Authenticode vs Catalog) and whether Windows treats it as an OS binary
Get-AuthenticodeSignature -FilePath 'C:\Windows\System32\mshta.exe' |
    Select-Object -Property Status, SignatureType, IsOSBinary, @{ n = 'Signer'; e = { $_.SignerCertificate.Subject } }

# Sysinternals: unsigned files only, checking catalogs too (-u -e -s for a folder tree)
sigcheck64.exe -accepteula -u -e -s C:\Users\Public
```

## Check it on a host

```powershell
# Process tree with parent name, path and command line (parent may be gone for boot processes)
$all = Get-CimInstance -ClassName Win32_Process
$byId = @{}; foreach ($p in $all) { $byId[$p.ProcessId] = $p }
$all | ForEach-Object {
    [pscustomobject]@{
        PID         = $_.ProcessId
        Name        = $_.Name
        ParentPID   = $_.ParentProcessId
        Parent      = if ($byId.ContainsKey($_.ParentProcessId)) { $byId[$_.ParentProcessId].Name } else { '<exited>' }
        Path        = $_.ExecutablePath
        CommandLine = $_.CommandLine
    }
} | Sort-Object -Property Parent, Name | Format-Table -AutoSize -Wrap

# Core processes outside their expected folder
$expected = @{ 'lsass.exe' = 'C:\Windows\System32'; 'services.exe' = 'C:\Windows\System32'; 'svchost.exe' = 'C:\Windows\System32'; 'explorer.exe' = 'C:\Windows' }
$all | Where-Object { $expected.ContainsKey($_.Name) -and $_.ExecutablePath -and
    (Split-Path -Path $_.ExecutablePath -Parent) -notin @($expected[$_.Name], 'C:\Windows\SysWOW64') } |
    Select-Object -Property ProcessId, Name, ExecutablePath
```

## Hunt it in the SIEM

```kql
// Defender XDR: Office, browsers or WMI starting shells and script hosts
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","wmiprvse.exe","w3wp.exe","sqlservr.exe","mshta.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
```

```spl
index=sysmon EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe" OR ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\w3wp.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe" OR Image="*\\regsvr32.exe")
| stats count min(_time) as first max(_time) as last by host, ParentImage, Image, CommandLine
| convert ctime(first) ctime(last)
```

```spl
index=sysmon EventCode=1 (Image="*\\lsass.exe" OR Image="*\\services.exe" OR Image="*\\svchost.exe")
  NOT Image="C:\\Windows\\System32\\*" NOT Image="C:\\Windows\\SysWOW64\\*"
| stats count by host, Image, ParentImage
```

## Related

- Registry side: [Windows registry keys that change behaviour](windows-registry-security-keys.md)
- Concepts: [Windows process architecture](../fundamentals/systems/windows-processes.md) · [Processes, threads and handles](../fundamentals/concepts/processes-threads.md)
- Commands: [Windows processes](../platforms/windows/processes.md)
- Detection: [KQL process events](../detection/kql/process-events.md) · [SPL Windows events](../detection/spl/windows-events.md) · [Sysmon](../fundamentals/systems/sysmon.md)
- Respond: [Suspicious process](../tasks/incident-response/suspicious-process.md) · [LOLBins execution hunting](../tasks/threat-hunting/lolbins-execution-hunting.md)

## Sources

- SANS: [Hunt Evil poster](https://www.sans.org/posters/hunt-evil/)
- Microsoft Learn: [ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference) · [Applications that can bypass App Control (recommended block rules)](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol) · [AppLocker default rules](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-applocker-default-rules) · [Get-AuthenticodeSignature](https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature) · [Sigcheck](https://learn.microsoft.com/sysinternals/downloads/sigcheck)
- LOLBAS project: [lolbas-project.github.io](https://lolbas-project.github.io/)
