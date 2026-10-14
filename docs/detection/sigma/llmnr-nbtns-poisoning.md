---
title: Detection Rule — LLMNR / NBT-NS Poisoning
type: entry
platforms:
  - Windows
  - Microsoft Defender
languages:
  - Sigma
  - KQL
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-13
difficulty: intermediate
tags:
  - llmnr
  - nbt-ns
  - responder
  - inveigh
  - poisoning
  - t1557.001
---

# Detection Rule — LLMNR / NBT-NS Poisoning

Detects tools such as Responder and Inveigh that answer LLMNR (UDP 5355) and NBT-NS (UDP 137) name queries to steal
NTLM hashes. Three angles: the tool running, a non-system process listening on those ports, and a honey name that
nobody should be able to resolve.

!!! warning "Before you deploy"
    Checked (2026-10-13) against Microsoft Learn (`DeviceNetworkEvents`, `Resolve-DnsName`, `Write-EventLog`) and the
    Atomic Red Team T1557.001 test; not run against a live fleet. On Windows the DNS Client service (`svchost.exe`) and `System` legitimately listen on 5355 and 137; the rules
    exclude them. An attacker on a Linux laptop is invisible to endpoint rules on your fleet — the honey-name check
    covers that case. The best fix is prevention: disable LLMNR and NetBIOS over TCP/IP by GPO.

- **ATT&CK**: [T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- **Concept**: [Man-in-the-Middle](../../fundamentals/concepts/man-in-the-middle.md)

## Sigma rule — poisoning tool execution

```yaml
title: LLMNR/NBT-NS Poisoning Tool Execution
id: 07c23daa-2a6c-4b2f-9699-f371d3c22ae0
status: experimental
description: Detects command lines and PowerShell commands used by Responder and Inveigh.
references:
  - https://attack.mitre.org/techniques/T1557/001/
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.credential-access
  - attack.t1557.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_cli:
    CommandLine|contains:
      - 'Invoke-Inveigh'
      - 'Inveigh.exe'
      - 'Responder.py'
      - 'Invoke-InveighRelay'
  selection_img:
    Image|endswith:
      - '\Inveigh.exe'
  condition: 1 of selection_*
falsepositives:
  - Authorised penetration tests
level: high
```

## KQL (Defender for Endpoint) — unexpected listener on 5355 / 137

```kql
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (5355, 137, 5353)
| where InitiatingProcessFileName !in~ ("svchost.exe", "System", "mDNSResponder.exe")
| project Timestamp, DeviceName, LocalIP, LocalPort, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
```

## Honey-name check (catches poisoners you do not manage)

A scheduled job on a few workstations resolves a random name that does not exist. On a clean network no one answers;
any answer comes from a poisoner. Log the result and alert on it.

```powershell
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$honeyName = 'fs-' + -join ((97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$responders = @()
try {
    $reply = Resolve-DnsName -Name $honeyName -LlmnrNetbiosOnly -QuickTimeout -ErrorAction Stop
    $responders = @($reply | Where-Object { $_.PSObject.Properties.Name -contains 'IPAddress' } |
        Select-Object -ExpandProperty IPAddress)
} catch {
    # Name not resolved: the expected, healthy result. Only the lookup is inside try, so a logging
    # failure below (event source not registered) still surfaces instead of being swallowed.
}
if ($responders.Count -gt 0) {
    Write-EventLog -LogName Application -Source 'CC-HoneyName' -EventId 4801 -EntryType Warning `
        -Message "LLMNR/NBT-NS answer for honey name $honeyName from: $($responders -join ', ')"
}
```

Run it with Windows PowerShell 5.1 (`Write-EventLog` and `New-EventLog` are not in PowerShell 7). Register the event
source once (`New-EventLog -LogName Application -Source 'CC-HoneyName'`), then alert on Application event 4801:

```spl
index=wineventlog source="XmlWinEventLog:Application" EventCode=4801 "CC-HoneyName"
| rex "from: (?<responder_ip>[0-9a-fA-F.:, ]+)"
| stats count min(_time) as first_seen by host, responder_ip
```

## Triage

1. Map the responder IP to a host and switch port; poisoning needs layer-2 adjacency, so it is on the same VLAN.
2. Treat accounts that authenticated to that IP as exposed. Clients log outbound NTLM in
   `Microsoft-Windows-NTLM/Operational` event 8001 when NTLM auditing is on; relayed logons show on the target server
   as `4624` (LogonType 3, NTLM) with the poisoner's IP as source.
3. Disable LLMNR (`Turn off multicast name resolution`) and NetBIOS over TCP/IP; require [SMB signing](../../fundamentals/smb.md).

## Test it

Atomic Red Team [T1557.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1557.001/T1557.001.md)
*LLMNR Poisoning with Inveigh (PowerShell)* runs Inveigh on a lab host: it should fire the process rule and the
listener query, and the honey-name job on another lab host should log event 4801. Lab only: Inveigh answers real
name queries on that segment.

## Sources

- [Microsoft Learn — DeviceNetworkEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [Microsoft Learn — Resolve-DnsName](https://learn.microsoft.com/powershell/module/dnsclient/resolve-dnsname)
- [Microsoft Learn — Write-EventLog (Windows PowerShell 5.1)](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/write-eventlog?view=powershell-5.1)
- [MITRE ATT&CK T1557.001](https://attack.mitre.org/techniques/T1557/001/)
