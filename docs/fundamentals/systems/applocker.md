---
title: Fundamentals — AppLocker & Application Control Baselines
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - applocker
  - application-whitelisting
  - hardening
---

# Fundamentals — AppLocker & Application Control Baselines

AppLocker enforces application control rules in Windows, restricting software execution based on file path, hash, or publisher digital signatures.

**Why it matters:** most malware arrives as a new executable or script in a user-writable folder (Downloads, `%TEMP%`, `%AppData%`). An allow-list that only runs software from protected locations or trusted publishers stops most of it before it starts. Microsoft does not treat AppLocker as a security boundary; for stronger enforcement use **App Control for Business** (formerly WDAC), but AppLocker is still a quick, high-value layer.

## 1. Rule Collections

- **Executable Rules (`.exe`, `.com`)**: Prevents binaries from running outside `Program Files` and `Windows`.
- **Script Rules (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`)**: Disallows script execution in user-writable directories (`%TEMP%`, `C:\Users\`). When script rules are enforced, PowerShell runs scripts that are not allowed in **Constrained Language Mode (CLM)**.
- **Windows Installer Rules (`.msi`, `.msp`, `.mst`)**: Blocks unapproved software installations.
- **Packaged App Rules (`.appx`, `.msix`)**: Regulates modern store applications.
- **DLL Rules (`.dll`, `.ocx`)**: Off by default; strongest coverage but a performance cost and much more testing.

Rule types, from strongest to weakest: **Publisher** (signature; survives updates), **Hash** (exact file; breaks on every update), **Path** (only as strong as the folder's permissions).

## 2. Path Rule Bypass Defense

Never whitelist paths like `C:\Windows\*` without denying known user-writable folders inside Windows (e.g., `C:\Windows\Tasks`, `C:\Windows\Temp`, `C:\Windows\System32\spool\drivers\color`). Prefer **Publisher (Digital Signature)** rules over path rules.

Also block or restrict signed Microsoft binaries that run arbitrary code (`mshta.exe`, `wscript.exe`, `cscript.exe`, `msbuild.exe`, `installutil.exe`, `regsvr32.exe`) for standard users; see [LOLBins hunting](../../tasks/threat-hunting/lolbins-execution-hunting.md).

## 3. Deploy safely

1. Start the **Application Identity** service (`AppIDSvc`) and set it to automatic; without it nothing is enforced.
2. Create the default rules (allow `Program Files` and `Windows` for everyone, everything for administrators), then add publisher rules for your software.
3. Set each collection to **Audit only** and collect events for a few weeks.
4. Fix what would have been blocked, then switch to **Enforce rules**, one collection at a time.

```powershell
# Effective policy on this machine (local + Group Policy)
Get-AppLockerPolicy -Effective -Xml | Out-File .\applocker-effective.xml

# Would this file be allowed for this user?
Get-AppLockerPolicy -Effective |
    Test-AppLockerPolicy -Path 'C:\Users\Public\tool.exe' -User 'CONTOSO\jdoe'

# Is enforcement actually running?
Get-Service -Name AppIDSvc | Select-Object Status, StartType

# Recent blocks (8004) and audit-mode "would block" events (8003)
Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 200 |
    Where-Object Id -in 8003, 8004 | Select-Object TimeCreated, Id, Message
```

Script and MSI events are in the `Microsoft-Windows-AppLocker/MSI and Script` log (8006 audit, 8007 blocked).

## 4. Detect tampering

- `AppIDSvc` stopped or set to disabled (System log 7036 / 7040).
- Policy changes: Group Policy updates and the `AppLocker` registry policy under `HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2`.
- A sudden drop to zero AppLocker events from a host that used to log them.

## Related

- [WDAC and Exploit Protection](../../platforms/windows/wdac-exploit-guard.md)
- [Suspicious PowerShell](../../tasks/incident-response/suspicious-powershell.md)

## Sources

- [Microsoft Learn — AppLocker overview](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)
- [Microsoft Learn — Using Event Viewer with AppLocker](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [Microsoft Learn — Test-AppLockerPolicy](https://learn.microsoft.com/powershell/module/applocker/test-applockerpolicy)
