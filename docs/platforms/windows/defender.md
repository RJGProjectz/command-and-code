---
title: Microsoft Defender Antivirus
platforms: [Windows, Windows Server, Microsoft Defender]
languages: [PowerShell, Windows CLI]
tasks: [Incident Response, Administration, Hardening, Troubleshooting]
category: Endpoint Protection
tags: [defender, antivirus, exclusions, tamper protection, mpcmdrun, asr, detections]
aliases: [Get-MpComputerStatus, defender exclusions, defender scan, defender detections, MpCmdRun, windows defender status]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Microsoft Defender Antivirus

Local Defender Antivirus (MDAV) commands. For the Defender XDR portal, advanced hunting and device actions see [Defender XDR](../microsoft-365/defender.md).

## Health and protection status

```powershell
Get-MpComputerStatus |
    Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                  IsTamperProtected, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AMProductVersion
```

`AMRunningMode` values: `Normal` (active), `Passive Mode` (another AV is primary, or MDE passive), `EDR Block Mode`, `SxS Passive Mode`.

## Exclusions

```powershell
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress
```

Recent Defender versions return `N/A: Must be an administrator to view exclusions` to non-admin sessions. Run elevated.

| Source | Registry location |
| --- | --- |
| Local | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Processes,Extensions}` |
| Group Policy | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\…` |

**Security relevance:** attackers add exclusions for their staging directory before dropping tools ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)). Broad exclusions such as `C:\Users\`, `C:\ProgramData\` or `*.exe` are findings in their own right.

## Recent detections

```powershell
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
    Select-Object InitialDetectionTime, ThreatID, ProcessName, Resources, ActionSuccess
Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive
```

## Run a scan

```powershell
Update-MpSignature
Start-MpScan -ScanType QuickScan
Start-MpScan -ScanType CustomScan -ScanPath 'C:\Users\Public'
```

**MpCmdRun.exe** (useful from cmd, scripts, or when the module is unavailable):

```text
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\Public
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Restore -ListAll
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -GetFiles
```

ScanType: `1` quick, `2` full, `3` custom path. `-GetFiles` collects a support CAB (`MpSupportFiles.cab`) under `C:\ProgramData\Microsoft\Windows Defender\Support`.

## Attack Surface Reduction rules state

```powershell
$p = Get-MpPreference
for ($i = 0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) {
    [pscustomobject]@{ RuleId = $p.AttackSurfaceReductionRules_Ids[$i]; Action = $p.AttackSurfaceReductionRules_Actions[$i] }
}
```

Action: `0` disabled, `1` block, `2` audit, `6` warn.

## Defender event log

Log: `Microsoft-Windows-Windows Defender/Operational`

| Event | Meaning |
| --- | --- |
| 1116 | Malware or PUA detected |
| 1117 | Action taken on malware |
| 5001 | Real-time protection disabled |
| 5007 | Configuration changed (look for exclusion paths in the message) |
| 5013 | Tamper protection blocked a change |

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 5001, 5007, 5013 } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

## Policy location (GPO)

```text
Computer Configuration
→ Administrative Templates
→ Windows Components
→ Microsoft Defender Antivirus
```

(Named *Windows Defender Antivirus* in older ADMX templates.) Settings managed by Intune or Defender for Endpoint security settings management do not appear in GPO.

## Related

- [Defender XDR](../microsoft-365/defender.md)
- [Malware Triage workflow](../../tasks/incident-response/malware-triage.md)
- [SPL: Defender events](../../detection/spl/windows-events.md#microsoft-defender-antivirus-events)

## Sources

- [Defender module](https://learn.microsoft.com/powershell/module/defender/)
- [MpCmdRun command-line](https://learn.microsoft.com/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [Defender Antivirus event IDs](https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
