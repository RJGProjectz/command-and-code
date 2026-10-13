---
title: Assurance Check — Endpoint EDR Agent Health Status
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
tasks:
  - Assurance
  - Incident Response
verified: true
last_verified: 2026-10-12
difficulty: basic
tags:
  - assurance
  - edr
  - defender
  - sentinelone
---

# Assurance Check — Endpoint EDR Agent Health Status

Inspects local service execution, driver loading, and cloud heartbeat telemetry for endpoint detection agents (Microsoft Defender, SentinelOne).

**Why:** an EDR agent that is installed but stopped, unlicensed, in passive mode or out of date gives no protection while the console may still list the device. Attackers stop or tamper with agents early ([T1562.001](https://attack.mitre.org/techniques/T1562/001/)). **Run as:** local administrator; read-only.

## Windows — Microsoft Defender Antivirus and Defender for Endpoint

```powershell
$sense  = Get-Service -Name 'Sense' -ErrorAction SilentlyContinue
$mp     = Get-MpComputerStatus -ErrorAction SilentlyContinue
$status = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue

[pscustomobject]@{
    MdeOnboarded         = ($null -ne $status -and $status.OnboardingState -eq 1)
    SenseRunning         = ($null -ne $sense -and $sense.Status -eq 'Running')
    AvRunningMode        = $mp.AMRunningMode                 # Normal, Passive or EDR Block Mode
    RealTimeProtection   = $mp.RealTimeProtectionEnabled
    BehaviorMonitor      = $mp.BehaviorMonitorEnabled
    TamperProtected      = $mp.IsTamperProtected
    SignatureAgeDays     = $mp.AntivirusSignatureAge
    SignatureLastUpdated = $mp.AntivirusSignatureLastUpdated
    EngineVersion        = $mp.AMEngineVersion
}
```

| Field | Healthy |
| --- | --- |
| `MdeOnboarded`, `SenseRunning` | `True` (Defender for Endpoint sensor reporting) |
| `AvRunningMode` | `Normal`; `Passive` is expected only when another AV is primary |
| `RealTimeProtection`, `BehaviorMonitor`, `TamperProtected` | `True` |
| `SignatureAgeDays` | 0–1; more than 3 means updates are failing |

## Windows — SentinelOne

```powershell
$s1 = Get-ChildItem -Path 'C:\Program Files\SentinelOne' -Filter 'SentinelCtl.exe' -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
Get-Service -Name 'SentinelAgent' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType
if ($s1) { & $s1.FullName status }
```

`SentinelCtl.exe status` shows whether the agent is loaded, its protection state and whether the monitor is running. The install folder name includes the agent version, hence the search.

## Linux

```bash
# Microsoft Defender for Endpoint on Linux
mdatp health --field healthy
mdatp health --field real_time_protection_enabled
mdatp health --field definitions_status   # want "up_to_date"

# SentinelOne
sudo /opt/sentinelone/bin/sentinelctl control status
systemctl is-active sentinelone
```

## Fleet view

Local checks prove one host. For coverage, compare the EDR console's device list with your asset inventory (AD computers, Intune, CMDB): devices missing from the console or with a last-seen time older than 7 days are the gaps.

```kql
// Microsoft Defender XDR: devices whose sensor has not reported recently
DeviceInfo
| summarize LastSeen = max(Timestamp) by DeviceName, OSPlatform, OnboardingStatus
| where LastSeen < ago(7d) or OnboardingStatus != "Onboarded"
```

## Remediate

| Finding | Action |
| --- | --- |
| Service stopped or agent missing | Reinstall or restart through your deployment tool; investigate why it stopped (check 7036/7040 service events, recent admin logons) |
| Passive mode with no other AV | Fix the policy (Intune / GPO `ForceDefenderPassiveMode`) |
| Tamper protection off | Turn it on centrally (Defender portal or Intune), not on the host |
| Old signatures | Check update source, proxy and WSUS / Configuration Manager rules |

## Related

- [Microsoft Defender Antivirus](../../platforms/windows/defender.md)
- [Agent tampering detection (SPL)](../../detection/spl/agent-tampering.md)

## Sources

- [Microsoft Learn — Get-MpComputerStatus](https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus)
- [Microsoft Learn — Defender for Endpoint on Linux: health and `mdatp` commands](https://learn.microsoft.com/defender-endpoint/linux-resources)
- [Microsoft Learn — DeviceInfo table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceinfo-table)
