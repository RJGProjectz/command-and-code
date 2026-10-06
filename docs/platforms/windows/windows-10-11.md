---
title: Windows 10 and 11 Version Notes
platforms: [Windows]
languages: [PowerShell]
tasks: [Administration, Troubleshooting]
category: System Information
tags: [windows 10, windows 11, build numbers, version differences, wmic]
aliases: [windows 11 build number, is this windows 11, DisplayVersion, wmic deprecated]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Windows 10 and 11 Version Notes

## Identify Windows 10 vs Windows 11

Windows 11 is any build **22000 or later**. Use the build number — not the product name.

```powershell
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[pscustomobject]@{
    Build          = [int]$cv.CurrentBuildNumber
    UBR            = $cv.UBR
    DisplayVersion = $cv.DisplayVersion
    IsWindows11    = [int]$cv.CurrentBuildNumber -ge 22000
}
```

!!! warning "ProductName lies on Windows 11"
    The registry value `ProductName` under `CurrentVersion` still reads **Windows 10** on Windows 11. `Win32_OperatingSystem.Caption` reports the correct name.

`UBR` (Update Build Revision) is the patch level: build `22631` + UBR `4317` = `22631.4317`.

## Build reference

| Release | Build |
| --- | --- |
| Windows 10 22H2 (final) | 19045 |
| Windows 11 21H2 | 22000 |
| Windows 11 22H2 | 22621 |
| Windows 11 23H2 | 22631 |
| Windows 11 24H2 | 26100 |

Windows 10 reached end of support on **14 October 2025**; after that only devices in Extended Security Updates receive patches.

`DisplayVersion` (e.g. `23H2`) replaced the older `ReleaseId` value, which stopped updating after 2009/20H2.

## Behaviour differences that affect scripts

| Topic | Note |
| --- | --- |
| `wmic.exe` | Deprecated; disabled by default or removed on newer Windows 11 releases. Use `Get-CimInstance`. |
| Windows PowerShell 5.1 | Still the in-box `powershell.exe`. PowerShell 7 (`pwsh.exe`) is a separate install. |
| Script block logging | 5.1 logs to `Microsoft-Windows-PowerShell/Operational`; 7 logs to `PowerShellCore/Operational`. |
| Default file encoding | 5.1 `Out-File` / `>` writes UTF-16LE; 7 writes UTF-8 without BOM. |

## Related

- [Windows system information](system-information.md)
- [PowerShell fundamentals and pitfalls](../../languages/powershell/fundamentals.md)

## Sources

- [Windows 11 release information](https://learn.microsoft.com/windows/release-health/windows11-release-information)
- [Windows 10 release information](https://learn.microsoft.com/windows/release-health/release-information)
- [WMIC deprecation](https://learn.microsoft.com/windows/whats-new/deprecated-features)
