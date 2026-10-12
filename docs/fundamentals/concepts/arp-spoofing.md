---
title: ARP Spoofing
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Threat Hunting, Troubleshooting]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, arp, mitm, layer-2]
aliases: [ARP poisoning, ARP cache poisoning, gratuitous ARP attack, ARP (Address Resolution Protocol)]
difficulty: intermediate
verified: false
---

# ARP Spoofing
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a host on your LAN lies about which MAC address owns an IP, so traffic meant for someone else goes to it.

## What it is

ARP maps IPv4 addresses to MAC addresses on a local segment, and it has no authentication: hosts accept replies they
never asked for. An attacker on the same VLAN sends forged replies saying "the gateway's IP is at my MAC". Victims
update their ARP cache and send their traffic through the attacker, who can read, change or drop it.

## How it works

```text
Normal:   [Victim] ──► gateway 10.0.0.1 = aa:aa:aa:aa:aa:aa ──► [Gateway]

Poisoned: [Attacker] ──(forged reply: 10.0.0.1 is at bb:bb:bb:bb:bb:bb)──► [Victim]
          [Victim] ──► [Attacker bb:bb..] ──(forwards)──► [Gateway]      = man-in-the-middle
```

1. Attacker joins the same broadcast domain (cable, Wi-Fi, compromised host).
2. Sends repeated unsolicited ARP replies to the victim, the gateway, or both.
3. Caches now point at the attacker; it forwards packets so nobody notices an outage.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1557.002](https://attack.mitre.org/techniques/T1557/002/) — Adversary-in-the-Middle: ARP Cache Poisoning |
| **What it leads to** | [Packet sniffing](packet-sniffing.md) of clear-text protocols, credential capture, session hijack, NTLM relay |
| **Where defenders meet it** | duplicate-IP warnings, intermittent connectivity, a switch log showing one MAC on many IPs |

## Do it

Find the related commands in the toolbox:

```bash
cc find arp
cc view docs/platforms/windows/networking.md
```

Look for one MAC claiming several IPs in the local ARP cache (broadcast and multicast entries filtered out):

```powershell
Get-NetNeighbor -AddressFamily IPv4 |
    Where-Object { $_.State -in 'Reachable', 'Stale', 'Permanent' -and $_.LinkLayerAddress -notmatch '^(FF-FF|01-00-5E|00-00-00)' } |
    Group-Object -Property LinkLayerAddress |
    Where-Object Count -gt 1 |
    Select-Object @{ n = 'MAC'; e = { $_.Name } }, @{ n = 'IPs'; e = { $_.Group.IPAddress -join ', ' } }
```

```bash
ip -4 neigh show | awk '$5 ~ /:/ {print $5, $1}' | sort | awk '{ips[$1]=ips[$1]" "$2; n[$1]++} END {for (m in n) if (n[m]>1) print m":"ips[m]}'
```

A router or firewall with several IPs on one interface is a normal false positive — check the gateway's MAC against
your network documentation.

## See it

| Source | What you see |
| :--- | :--- |
| ARP cache (`arp -a`, `ip neigh`) | gateway IP now maps to a workstation's MAC; one MAC on several IPs |
| Packet capture | a stream of ARP replies with no matching requests, every few seconds |
| Managed switch | DHCP snooping / Dynamic ARP Inspection drop counters, MAC-flap log messages |
| Linux live response | the saved ARP cache from the [live response kit](../../tasks/forensics/linux-live-response-forensics.md) |

## Detect it

- Investigate: [Network Investigation](../../tasks/investigation/network-investigation.md) — live state, then packet capture
- Troubleshoot the symptom: [Windows Connectivity](../../tasks/troubleshooting/windows-connectivity.md)
- Inspect: [Windows networking — IP configuration, routes and ARP](../../platforms/windows/networking.md) · [Linux networking](../../platforms/linux/networking.md)
- Harden: enable Dynamic ARP Inspection and DHCP snooping on access switches; segment with [microsegmentation](../networking/microsegmentation.md)
- No SIEM rule page yet: endpoint EDR rarely sees layer-2 traffic, so switch logs are the reliable source.

## Related concepts

- [Packet Sniffing](packet-sniffing.md)
- [Port Scanning](port-scanning.md)
