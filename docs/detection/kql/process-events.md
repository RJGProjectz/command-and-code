---
title: KQL Process Event Hunting
platforms: [Microsoft Defender, Windows]
languages: [KQL]
tasks: [Threat Hunting, Detection Engineering, Investigation, Incident Response]
category: Process Execution
tags: [kql, deviceprocessevents, powershell, lolbins, office child process, process tree]
aliases: [defender process query, encoded powershell kql, suspicious powershell kql, office spawning powershell, process tree kql]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# KQL Process Event Hunting

Table: **`DeviceProcessEvents`** — one row per process creation. Key columns:

| Column | Meaning |
| --- | --- |
| `FileName`, `FolderPath`, `ProcessCommandLine`, `ProcessId`, `SHA256` | the new process |
| `AccountName`, `AccountDomain` | account that ran the new process |
| `InitiatingProcessFileName`, `InitiatingProcessCommandLine`, `InitiatingProcessId` | its parent |
| `InitiatingProcessParentFileName` | its grandparent |

## Encoded PowerShell

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

The regex catches every abbreviation of `-EncodedCommand` (`-e`, `-ec`, `-enc`, …) followed by a base64 blob. Decode the payload with [`decode-powershell.py`](../../toolbox/python.md#decode-powershellpy) or the [bash one-liner](../../languages/bash/text-processing.md#decode-base64-and-powershell-encoded-commands). MITRE: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1027](https://attack.mitre.org/techniques/T1027/).

## PowerShell download cradles

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("DownloadString", "DownloadFile", "Invoke-WebRequest", "iwr", "Net.WebClient", "Start-BitsTransfer", "FromBase64String")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## Office applications spawning shells

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

MITRE: [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (malicious file).

## Living-off-the-land binaries (LOLBins)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "decode"))
     or (FileName =~ "mshta.exe" and ProcessCommandLine has_any ("http", "javascript", "vbscript"))
     or (FileName =~ "rundll32.exe" and ProcessCommandLine has "javascript")
     or (FileName =~ "regsvr32.exe" and ProcessCommandLine has_any ("scrobj", "http"))
     or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "transfer")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

MITRE: [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution), [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer).

## Process tree for a PID on one device

```kql
let device = "ws-042";
let targetPid = 1234;
DeviceProcessEvents
| where Timestamp > ago(3d)
| where DeviceName startswith device
| where ProcessId == targetPid or InitiatingProcessId == targetPid
| project Timestamp, Relation = iff(ProcessId == targetPid, "self", "child"),
          InitiatingProcessFileName, InitiatingProcessId, FileName, ProcessId, ProcessCommandLine
| order by Timestamp asc
```

PIDs are reused — check that timestamps are consistent. The device timeline in the Defender portal is often faster for a single host.

## Execution from user-writable paths

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Users\Public\", @"\ProgramData\", @"\Downloads\")
| where FileName endswith ".exe"
| summarize Executions = count(), Devices = dcount(DeviceName), SampleCommand = any(ProcessCommandLine) by FileName, SHA256
| order by Devices asc
```

Sorting by `Devices asc` surfaces rare binaries first.

## Find every execution of a hash

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where SHA256 == "<sha256>"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Devices = make_set(DeviceName) by FileName, FolderPath
```

Replace `<sha256>` with the hash.

## Rare parent-child pairs

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| summarize Count = count(), Devices = dcount(DeviceName) by InitiatingProcessFileName, FileName
| where Count < 5
| order by Count asc
```

## Related

- [Suspicious PowerShell workflow](../../tasks/incident-response/suspicious-powershell.md)
- [SPL PowerShell searches](../spl/powershell.md)
- [S1QL hunting](../s1ql/hunting.md)
- [Windows processes](../../platforms/windows/processes.md)

## Sources

- [DeviceProcessEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [LOLBAS project](https://lolbas-project.github.io/)
