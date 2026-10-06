---
title: Windows Files and Permissions
platforms: [Windows, Windows Server]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Investigation, Forensics, Hardening]
category: Filesystem
tags: [files, hashes, acl, icacls, alternate data streams, zone identifier, recent files]
aliases: [file hash, recently modified files, file permissions, mark of the web, downloaded from, Get-FileHash]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows Files and Permissions

## Hash a file

```powershell
Get-FileHash -Path 'C:\Users\Public\update.exe' -Algorithm SHA256
Get-ChildItem -Path 'C:\Users\Public' -File -Recurse | Get-FileHash -Algorithm SHA256
```

**Windows CLI:** `certutil -hashfile C:\Users\Public\update.exe SHA256`

## Find recently created or modified files

```powershell
$since = (Get-Date).AddHours(-24)
Get-ChildItem -Path 'C:\Users', 'C:\ProgramData', 'C:\Windows\Temp' -File -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $since -or $_.CreationTime -gt $since } |
    Select-Object FullName, Length, CreationTime, LastWriteTime |
    Sort-Object LastWriteTime -Descending
```

Executables and scripts in user-writable locations:

```powershell
Get-ChildItem -Path "$env:SystemDrive\Users" -Recurse -Force -File -Include *.exe, *.dll, *.ps1, *.bat, *.vbs, *.js, *.hta -ErrorAction SilentlyContinue |
    Where-Object FullName -match '\\(AppData|Downloads|Desktop|Public)\\' |
    Select-Object FullName, CreationTime, Length
```

Timestamps can be altered (timestomping, [T1070.006](https://attack.mitre.org/techniques/T1070/006/)); treat them as leads, not proof.

## Where was this file downloaded from? (Mark of the Web)

Files downloaded by browsers and many mail clients carry a `Zone.Identifier` alternate data stream:

```powershell
Get-Item -Path 'C:\Users\<USER>\Downloads\invoice.zip' -Stream *
Get-Content -Path 'C:\Users\<USER>\Downloads\invoice.zip' -Stream Zone.Identifier
```

```text
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://example.com/
HostUrl=https://example.com/files/invoice.zip
```

`ZoneId=3` = Internet. `HostUrl` is often the exact download URL — a high-value pivot.

## Check file and folder permissions

```powershell
(Get-Acl -Path 'C:\Program Files\Vendor').Access |
    Select-Object IdentityReference, FileSystemRights, AccessControlType, IsInherited
(Get-Acl -Path 'C:\Program Files\Vendor\app.exe').Owner
```

**Windows CLI:**

```text
icacls "C:\Program Files\Vendor"
```

`icacls` flags: `(F)` full, `(M)` modify, `(RX)` read & execute, `(W)` write, `(OI)(CI)` inherited by files and folders.

**Security relevance:** `Everyone`, `Users` or `Authenticated Users` with `(F)`, `(M)` or `(W)` on a folder containing a service or scheduled-task binary is a privilege-escalation path.

## Search file contents

```powershell
Select-String -Path 'C:\Scripts\*.ps1' -Pattern 'DownloadString', 'FromBase64String', 'IEX' -SimpleMatch
```

**Windows CLI:** `findstr /s /i /m "password" C:\Shares\*.txt`

## Signature check

```powershell
Get-ChildItem 'C:\ProgramData' -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
    Get-AuthenticodeSignature |
    Where-Object Status -ne 'Valid' |
    Select-Object Path, Status
```

## Execution artifacts (forensics)

| Artifact | Location | Notes |
| --- | --- | --- |
| Prefetch | `C:\Windows\Prefetch\*.pf` | Workstations; usually disabled on Server |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program inventory with SHA1 |
| Recent files (LNK) | `%APPDATA%\Microsoft\Windows\Recent\` | Files the user opened |
| PowerShell history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Interactive commands, per user |

```powershell
Get-ChildItem -Path 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -Force -ErrorAction SilentlyContinue |
    ForEach-Object { "==== $($_.FullName)"; Get-Content -Path $_.FullName -Tail 50 }
```

Parse Prefetch and Amcache with dedicated tools (for example Eric Zimmerman's PECmd and AmcacheParser).

## Related

- [Malware Triage workflow](../../tasks/incident-response/malware-triage.md)
- [Linux filesystem](../linux/filesystem.md)
- [KQL file events](../../detection/kql/file-registry-events.md)

## Sources

- [Get-FileHash](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash)
- [icacls](https://learn.microsoft.com/windows-server/administration/windows-commands/icacls)
- [about_FileSystem_Provider (streams)](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_filesystem_provider)
