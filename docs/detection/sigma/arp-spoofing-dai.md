---
title: Detection Rule — ARP Spoofing (DAI and arpwatch)
type: entry
platforms:
  - Linux
  - Splunk
languages:
  - Sigma
  - SPL
  - KQL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-13
difficulty: intermediate
tags:
  - arp-spoofing
  - dai
  - dhcp-snooping
  - arpwatch
  - layer-2
  - t1557.002
---

# Detection Rule — ARP Spoofing (DAI and arpwatch)

Detects ARP cache poisoning from the network side. Endpoint EDR rarely sees layer-2 traffic, so the reliable sources are
the switch (Dynamic ARP Inspection drops, MAC flaps) and, where there is no managed switch, `arpwatch` on a Linux host.

!!! warning "Before you deploy"
    Checked (2026-10-13) against Cisco DAI documentation and message samples and the arpwatch message format; not run on a live
    switch. Message mnemonics are Cisco IOS / IOS-XE, and some releases log the deny as `%SW_DAI-4-INVALID_ARP`. Other vendors log the same events under different names. The Sigma
    `logsource` below is a custom one (`product: cisco`, `service: syslog`); map it to your syslog index or table.
    DAI must be enabled per VLAN (`ip arp inspection vlan <id>`) with DHCP snooping before any of these messages appear.

- **ATT&CK**: [T1557.002 — Adversary-in-the-Middle: ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/)
- **Concept**: [ARP Spoofing](../../fundamentals/concepts/arp-spoofing.md)

## Log sources

| Source | Message | Meaning |
| :--- | :--- | :--- |
| Cisco switch, DAI | `%SW_DAI-4-DHCP_SNOOPING_DENY` | ARP whose IP/MAC pair is not in the DHCP snooping binding table — the core spoofing signal |
| Cisco switch, DAI | `%SW_DAI-4-INVALID_ARP` | Same drop on releases that use this mnemonic |
| Cisco switch, DAI | `%SW_DAI-4-ACL_DENY` | ARP denied by a static ARP ACL (hosts with fixed IPs) |
| Cisco switch, DAI | `%SW_DAI-4-PACKET_RATE_EXCEEDED` | ARP rate limit hit on a port; the port usually goes err-disabled |
| Cisco switch | `%SW_MATM-4-MACFLAP_NOTIF` | One MAC seen on two ports in quick succession |
| Linux `arpwatch` | `flip flop`, `changed ethernet address` | An IP's MAC changed — on the gateway IP this is the classic poisoning sign |

## Sigma rule

```yaml
title: ARP Spoofing Indicator from Switch DAI or arpwatch
id: 48931f6a-bfda-4bff-9d75-07d1c35b5446
status: experimental
description: Detects Dynamic ARP Inspection denials, ARP rate-limit violations and arpwatch MAC-change messages that indicate ARP cache poisoning.
references:
  - https://attack.mitre.org/techniques/T1557/002/
author: RJGProjectz
date: 2026-10-11
tags:
  - attack.credential-access
  - attack.collection
  - attack.t1557.002
logsource:
  product: cisco
  service: syslog
detection:
  dai:
    - '%SW_DAI-4-DHCP_SNOOPING_DENY'
    - '%SW_DAI-4-INVALID_ARP'
    - '%SW_DAI-4-ACL_DENY'
    - '%SW_DAI-4-PACKET_RATE_EXCEEDED'
  arpwatch:
    - 'arpwatch: flip flop'
    - 'arpwatch: changed ethernet address'
  condition: dai or arpwatch
falsepositives:
  - Hosts with static IPs on a DAI VLAN that are missing from the ARP ACL
  - DHCP snooping binding table lost after a switch reload (bindings not persisted)
  - VRRP/HSRP failover and NIC teaming (arpwatch flip flop on the virtual IP)
level: high
```

## SPL

```spl
index=network sourcetype=cisco:ios ("%SW_DAI-4-DHCP_SNOOPING_DENY" OR "%SW_DAI-4-INVALID_ARP" OR "%SW_DAI-4-ACL_DENY" OR "%SW_DAI-4-PACKET_RATE_EXCEEDED")
| rex "on (?<port>[A-Za-z]+\d[\d/]*)"
| rex "vlan (?<vlan>\d+)\.\(\[(?<src_mac>[0-9a-f.]+)/(?<src_ip>[\d.]+)"
| eval signal=if(searchmatch("PACKET_RATE_EXCEEDED"), "rate", "deny")
| fillnull value="-" vlan src_mac
| stats count min(_time) as first_seen max(_time) as last_seen values(src_ip) as claimed_ips by host, signal, port, vlan, src_mac
| where count >= 3 OR signal="rate"
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```

A deny line looks like `1 Invalid ARPs (Req) on Gi1/0/5, vlan 10.([5835.d9b0.b9d1/10.0.10.1/0000.0000.0000/10.0.10.7/...])`:
sender MAC, sender IP, target MAC, target IP. A rate-limit line (`29 packets received in 5 milliseconds on Gi1/0/10.`)
has no VLAN or MAC, so `fillnull` keeps it in the results and one is enough to alert, because the port is usually
err-disabled already. `claimed_ips` showing the gateway IP from an access port is the confirmation. For `arpwatch`:

```spl
index=linux sourcetype=syslog process=arpwatch ("flip flop" OR "changed ethernet address")
| rex "(?:flip flop|changed ethernet address) (?<ip>[\d.]+) (?<new_mac>[0-9a-f:]+) \((?<old_mac>[0-9a-f:]+)\)"
| stats count values(new_mac) as macs by host, ip
```

## KQL (Microsoft Sentinel, Syslog table)

```kql
Syslog
| where SyslogMessage has_any ("%SW_DAI-4-DHCP_SNOOPING_DENY", "%SW_DAI-4-INVALID_ARP", "%SW_DAI-4-ACL_DENY", "%SW_DAI-4-PACKET_RATE_EXCEEDED", "flip flop", "changed ethernet address")
| extend Signal = case(SyslogMessage has "PACKET_RATE_EXCEEDED", "rate",
                       SyslogMessage has_any ("flip flop", "changed ethernet address"), "arpwatch", "deny"),
         Port = extract(@"on ([A-Za-z]+\d[\d/]*)", 1, SyslogMessage),
         Vlan = extract(@"vlan (\d+)", 1, SyslogMessage),
         SrcMac = extract(@"\(\[([0-9a-f.]+)/", 1, SyslogMessage),
         ClaimedIp = coalesce(extract(@"\(\[[0-9a-f.]+/([\d.]+)/", 1, SyslogMessage),
                              extract(@"(?:flip flop|changed ethernet address) ([\d.]+)", 1, SyslogMessage))
| summarize Count = count(), ClaimedIps = make_set(ClaimedIp), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by Computer, Signal, Port, Vlan, SrcMac
| where Count >= 3 or Signal == "rate"
```

## Triage

1. Is a claimed IP the default gateway or a DNS/DHCP server? If yes, treat as an active incident.
2. Find the switch port of `src_mac` (`show mac address-table address <mac>`) and the device behind it.
3. Follow [Network Investigation](../../tasks/investigation/network-investigation.md) for packet capture and ARP-cache evidence.

## Test it

Atomic Red Team has no test for [T1557.002](https://attack.mitre.org/techniques/T1557/002/). In an **isolated lab VLAN**
with DAI enabled, send one gratuitous ARP from a test Linux host that claims an address it does not own (iputils
`arping`; `-U` unsolicited, `-s` sender IP). It briefly poisons other lab clients, so never run it on a production VLAN.

```bash
sudo arping -U -c 3 -I eth0 -s <LAB_GATEWAY_IP> <LAB_GATEWAY_IP>
```

The switch should log `DHCP_SNOOPING_DENY` (or `INVALID_ARP`) for that port; `arpwatch` on the VLAN logs `changed ethernet address`.

## Sources

- [Cisco — Troubleshoot Dynamic ARP Inspection (DAI) on Catalyst 9000 switches](https://www.cisco.com/c/en/us/support/docs/switches/lan-switch-software/222274-troubleshoot-dynamic-arp-inspection-dai.html)
- [arping(8) — iputils](https://man7.org/linux/man-pages/man8/arping.8.html)
- [Sigma specification](https://github.com/SigmaHQ/sigma-specification)
