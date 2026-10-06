---
title: KQL Network Event Hunting
platforms: [Microsoft Defender, Windows]
languages: [KQL]
tasks: [Threat Hunting, Investigation, Detection Engineering, Incident Response]
category: Network
tags: [kql, devicenetworkevents, beaconing, listening ports, rdp, dns, outbound connections]
aliases: [network connections kql, listening ports kql, beaconing detection, powershell network connection, rare destination, dns kql]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# KQL Network Event Hunting

Table: **`DeviceNetworkEvents`**. Useful `ActionType` values: `ConnectionSuccess`, `ConnectionFailed`, `ConnectionRequest`, `InboundConnectionAccepted`, `ListeningConnectionCreated`.

## Listening ports across the fleet

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ListeningConnectionCreated"
| summarize Devices = dcount(DeviceName), DeviceSample = make_set(DeviceName, 10) by LocalPort, InitiatingProcessFileName
| order by Devices asc
```

Rare listener/process combinations are the interesting ones. Endpoint equivalent: [Windows](../../platforms/windows/networking.md#find-listening-ports), [Linux](../../platforms/linux/networking.md#find-listening-ports).

## Scripting engines making external connections

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
```

## Connections to an indicator

```kql
let iocs = dynamic(["<TARGET_IP>", "<SECONDARY_IP>"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (iocs)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Connections = count()
          by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

## Rare external destinations

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize Devices = dcount(DeviceName), Connections = count(), Processes = make_set(InitiatingProcessFileName, 5) by RemoteIP, RemotePort
| where Devices == 1
| order by Connections desc
```

## Possible beaconing

Regular connections from one process to one destination:

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess" and RemoteIPType == "Public"
| summarize Connections = count(), Buckets = dcount(bin(Timestamp, 5m))
          by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
| where Buckets > 100                    // active in > 100 of 288 five-minute buckets
| order by Buckets desc
```

Expect legitimate hits (update agents, telemetry, chat clients). Allow-list them with a `let` list after review. MITRE: [T1071](https://attack.mitre.org/techniques/T1071/).

## Inbound RDP

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "InboundConnectionAccepted" and LocalPort == 3389
| summarize Connections = count(), Sources = make_set(RemoteIP, 20) by DeviceName
```

## DNS queries

Defender for Endpoint records DNS lookups in `DeviceEvents` with `ActionType == "DnsQueryResponse"`; the query details are in `AdditionalFields`.

```kql
DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == "DnsQueryResponse"
| extend Query = tostring(parse_json(AdditionalFields).DnsQueryString)
| where Query has "example.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, Query, AdditionalFields
```

DNS capture coverage varies by OS and sensor version — run `take 10` first and check the `AdditionalFields` keys in your tenant. `RemoteUrl` in `DeviceNetworkEvents` often holds the hostname as well.

## Related

- [Network Investigation workflow](../../tasks/investigation/network-investigation.md)
- [Suspicious Outbound Connection workflow](../../tasks/investigation/suspicious-outbound-connection.md)
- [SPL network and DNS](../spl/network-dns.md)

## Sources

- [DeviceNetworkEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [DeviceEvents table](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table)
