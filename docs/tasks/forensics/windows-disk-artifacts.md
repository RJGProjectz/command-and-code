---
title: Windows Forensic Disk Artifacts and Evidence Triage
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - Windows CLI
  - Python
tasks:
  - Forensics
  - Investigation
  - Incident Response
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - forensics
  - mft
  - prefetch
  - amcache
  - shimcache
  - usn-journal
  - shellbags
  - triage
---

# Windows Forensic Disk Artifacts and Evidence Triage

When an adversary executes malware, creates persistence, or deletes tooling, Windows leaves low-level metadata footprints across NTFS file system structures and system hives.

---

## 1. High-Yield Forensic Artifact Matrix

| Artifact | Forensic Location | Operational Evidence Provided |
| :--- | :--- | :--- |
| **$MFT & $LogFile** | `C:\$MFT` | Master file record, creation timestamps ($STANDARD_INFORMATION vs $FILE_NAME timestomping), file deletion tracking. |
| **USN Journal** | `C:\$Extend\$UsnJrnl:$J` | Complete chronological delta of file creations, modifications, renames, and deletions. |
| **Prefetch Files** | `C:\Windows\Prefetch\*.pf` | Proof of binary execution, run count, first/last execution timestamps, loaded DLL dependencies. |
| **Amcache.hve** | `C:\Windows\appcompat\Programs\Amcache.hve` | Unexecuted file hashes (SHA-1), compiled binary PE metadata, first execution time. |
| **Shimcache / AppCompat** | Registry `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Evidence of binary presence and execution path across system lifecycles. |
| **Shellbags** | Registry `UsrClass.dat` under `Local Settings\Software\Microsoft\Windows\Shell\Bags` | Proof of directory browsing and folder access in Windows Explorer (even for deleted folders). |
| **SRUM** | `C:\Windows\System32\sru\SRUDB.dat` | System Resource Usage Monitor: Network bytes sent/received by process, execution duration over 30 days. |

---

## 2. Prefetch Execution Analysis

Windows Workstation builds Prefetch files to optimize application loading. Each file proves program execution.

```powershell
# 1. Inspect Prefetch directory for suspicious executable executions
Get-ChildItem -Path C:\Windows\Prefetch\ -Filter "*.pf" |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 25 Name, LastWriteTime, Length

# 2. Parse Prefetch files using Eric Zimmerman's PECmd (CLI)
.\PECmd.exe -d C:\Windows\Prefetch --csv C:\Forensics\Parsed_Prefetch -q

# 3. Quick PowerShell triage without third-party tooling
# Check if a specific LOLBin (e.g. certutil, powershell, bitsadmin) ran recently
Get-ChildItem -Path C:\Windows\Prefetch -Filter "*POWERSHELL*.pf" | Select-Object Name, LastWriteTime
Get-ChildItem -Path C:\Windows\Prefetch -Filter "*CERTUTIL*.pf" | Select-Object Name, LastWriteTime
```

---

## 3. Extracting and Parsing NTFS $MFT & USN Journal

```powershell
# 1. Extract raw $MFT using RawCopy or KAPE from locked system volume
.\RawCopy.exe /FileNamePath:C:\$MFT /OutputPath:C:\Forensics\Triage_MFT\

# 2. Parse $MFT using MFTECmd into structured CSV
.\MFTECmd.exe -f C:\Forensics\Triage_MFT\$MFT --csv C:\Forensics\Output\ --csvf mft_analysis.csv

# 3. Query USN Journal directly via fsutil (live triage)
# Query USN change journal active parameters on drive C:
fsutil usn queryjournal C:

# Enumerate file operations matching malicious patterns or staging folders
fsutil usn readdata "C:\Users\Public\malicious.exe"
```

---

## 4. Timestomp Detection ($STANDARD_INFO vs $FILE_NAME)

Adversaries alter file timestamps (timestomping) using PowerShell or tools to blend in with `C:\Windows\System32`.
NTFS stores two distinct timestamp sets for every file:
- `$STANDARD_INFORMATION ($SI)`: Accessible to userland APIs; easily modified.
- `$FILE_NAME ($FN)`: Modified only by the NTFS kernel driver when files are created, renamed, or moved.

```text
TIMESTOMP SIGNATURE:
If $SI.CreationTime < $FN.CreationTime
=> The file was retroactively backdated (Timestomped).
```

---

## 5. Volume Shadow Copy (VSS) Historical Carving

When attackers delete payloads or ransomware wiper scripts, recover previous file versions from Volume Shadow Copies:

```powershell
# 1. Enumerate active Volume Shadow Copies
vssadmin list shadows

# 2. Create symbolic link to mount a historical snapshot
# Link \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1 to C:\ShadowSnap
cmd /c mklink /d C:\ShadowSnap \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# 3. Recover deleted event logs, SAM registry hives, and executed scripts
Copy-Item -Path "C:\ShadowSnap\Windows\System32\config\SAM" -Destination "C:\Forensics\Recovered_SAM"
Copy-Item -Path "C:\ShadowSnap\Windows\System32\config\SYSTEM" -Destination "C:\Forensics\Recovered_SYSTEM"

# 4. Remove symbolic link after extraction
cmd /c rmdir C:\ShadowSnap
```
