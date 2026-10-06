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

Local Defender Antivirus (MDAV) commands for endpoint protection, health checks, and exclusion audits. For the Defender XDR cloud portal, advanced hunting, and device actions see [Defender XDR](../microsoft-365/defender.md). Follow the systematic 5-stage methodology: check daemon services and protection engines, identify critical filesystem locations, audit active exclusions and policy configurations, triage recent detections and event logs, and execute safe scans.

## 1. Check Process, Service & Socket State

Verify that the underlying Windows Defender services and real-time security components are actively running:

```powershell
# Verify Defender and EDR service operational states
Get-Service -Name WinDefend, Sense, WdNisSvc -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType, DisplayName
```

### Health and protection status

Query engine health, signature freshness, and tamper protection:

```powershell
Get-MpComputerStatus |
    Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                  IsTamperProtected, AntivirusSignatureVersion, AntivirusSignatureLastUpdated, AMProductVersion
```

`AMRunningMode` values: `Normal` (active primary protection), `Passive Mode` (third-party AV or MDE passive), `EDR Block Mode`, `SxS Passive Mode`.

## 2. Known Locations & Key Filesystem Paths

Reference table of critical Defender binaries, support logs, and registry storage roots:

| Component | Standard Path / Key | Purpose |
| :--- | :--- | :--- |
| **Command-Line Engine** | `%ProgramFiles%\Windows Defender\MpCmdRun.exe` | Standalone CLI utility for scans and triage |
| **Platform Binaries** | `C:\ProgramData\Microsoft\Windows Defender\Platform\<Version>\` | Active antivirus engine executables |
| **Support Diagnostics** | `C:\ProgramData\Microsoft\Windows Defender\Support\` | Diagnostics repository for `MpSupportFiles.cab` |
| **Local Exclusions** | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\` | Machine-level local exclusions |
| **Policy Exclusions** | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\` | Domain / GPO delivered exclusions |
| **Operational Event Log** | `Microsoft-Windows-Windows Defender/Operational` | Tamper, detection, and state change audit log |

## 3. Configuration Inspection & Policy / Exclusions

### Exclusions

Inspect configured path, process, extension, and IP address exclusions:

```powershell
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress
```

Recent Defender versions return `N/A: Must be an administrator to view exclusions` to standard users. Run elevated.

| Source | Registry location |
| :--- | :--- |
| **Local** | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Processes,Extensions}` |
| **Group Policy** | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\…` |

**Security relevance:** Attackers frequently inject exclusions for their staging folder before dropping tooling ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)). Broad exclusions such as `C:\Users\`, `C:\ProgramData\`, or `*.exe` represent severe security deficiencies.

### Attack Surface Reduction rules state

```powershell
$p = Get-MpPreference
for ($i = 0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) {
    [pscustomobject]@{ RuleId = $p.AttackSurfaceReductionRules_Ids[$i]; Action = $p.AttackSurfaceReductionRules_Actions[$i] }
}
```

Action values: `0` disabled, `1` block, `2` audit, `6` warn.

### Policy location (GPO)

```text
Computer Configuration
→ Administrative Templates
→ Windows Components
→ Microsoft Defender Antivirus
```

*(Named Windows Defender Antivirus in older ADMX templates.) Settings managed by Intune or Defender for Endpoint security settings management do not appear in GPO.*

## 4. Operational Diagnostics & Event Auditing

### Recent detections

Query the local detection repository to identify recent threats and affected files:

```powershell
Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending |
    Select-Object InitialDetectionTime, ThreatID, ProcessName, Resources, ActionSuccess
Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive
```

### Defender event log

Channel: `Microsoft-Windows-Windows Defender/Operational`

| Event ID | Meaning | Security Implication |
| :--- | :--- | :--- |
| **1116** | Malware or PUA detected | Action initiated by scanner |
| **1117** | Action taken on malware | Quarantine, clean, or block outcome |
| **5001** | Real-time protection disabled | Defense evasion indicator |
| **5007** | Configuration changed | Look for newly added exclusion paths in message |
| **5013** | Tamper protection triggered | Unauthorized attempt to disable Defender blocked |

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 5001, 5007, 5013 } -MaxEvents 50 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

## 5. Hardening Baselines & Safe Scan Operations

### Run a scan

Update threat intelligence definitions and initiate on-demand triage scans:

```powershell
Update-MpSignature
Start-MpScan -ScanType QuickScan
Start-MpScan -ScanType CustomScan -ScanPath 'C:\Users\Public'
```

**MpCmdRun.exe** (essential when PowerShell is constrained or unavailable):

```text
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -SignatureUpdate
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\Public
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Restore -ListAll
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -GetFiles
```

ScanType flags: `1` Quick scan, `2` Full scan, `3` Custom path. `-GetFiles` packages triage logs and quarantine metadata into a support CAB (`MpSupportFiles.cab`) in `C:\ProgramData\Microsoft\Windows Defender\Support`.

## Related

- [Defender XDR](../microsoft-365/defender.md)
- [Malware Triage workflow](../../tasks/incident-response/malware-triage.md)
- [SPL: Defender events](../../detection/spl/windows-events.md#microsoft-defender-antivirus-events)

## Sources

- [Defender module](https://learn.microsoft.com/powershell/module/defender/)
- [MpCmdRun command-line](https://learn.microsoft.com/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [Defender Antivirus event IDs](https://learn.microsoft.com/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
