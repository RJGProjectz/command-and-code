---
title: Port Scanning
type: concept
platforms: [Windows, Linux, Microsoft Defender]
languages: [PowerShell, Bash, KQL]
tasks: [Investigation, Threat Hunting, Hardening]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, nmap, discovery, scanning]
aliases: [Nmap, network scan, network service discovery, banner grabbing, Network Scanning and Enumeration, Network Hacking]
difficulty: basic
verified: false
---

# Port Scanning
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** knocking on many ports of many hosts to learn which services are listening — the attacker's map and the defender's exposure check.

## What it is

Every network service listens on a port. A scanner such as Nmap sends probes to a range of ports and reads the replies:
open, closed, or filtered by a firewall. With version and script probes it also reads service banners. Attackers do it
right after initial access to find the next target; defenders do it to see their own attack surface first.

## How it works

```text
TCP connect scan:  SYN ──► ◄── SYN/ACK = open      ◄── RST = closed      (silence) = filtered
SYN ("half-open"): SYN ──► ◄── SYN/ACK then RST ──►  — never completes the handshake
UDP scan:          probe ──► ◄── ICMP port unreachable = closed          (silence) = open or filtered
```

The pattern on the wire is the giveaway: **one source, many destinations or many ports, short time**.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery |
| **What it leads to** | targeting of exposed RDP, SMB, WinRM, databases; [lateral movement](../../tasks/threat-hunting/lateral-movement.md) |
| **Where defenders meet it** | firewall deny bursts, IDS alerts, an EDR alert on a workstation touching hundreds of hosts |

## Do it

```bash
cc find "listening ports"
cc view docs/platforms/linux/networking.md
```

Check your own exposure — what this host listens on:

```powershell
Get-NetTCPConnection -State Listen |
    Select-Object -Property LocalAddress, LocalPort, @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess).ProcessName } } |
    Sort-Object -Property LocalPort
Test-NetConnection -ComputerName 'lab-host.example' -Port 3389
```

Scan only hosts you own or are authorised in writing to test:

```bash
nmap -sT -Pn --top-ports 100 'lab-host.example'
```

## See it

| Source | What you see |
| :--- | :--- |
| Firewall / WFP log (Windows 5157) | many blocked connections from one source to sequential ports |
| Defender `DeviceNetworkEvents` | one device, one process, many distinct `RemotePort` / `RemoteIP` values |
| Target host | short-lived connections that close without data; service logs with empty sessions |

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType in ("ConnectionSuccess", "ConnectionFailed", "ConnectionAttempt")
| summarize Ports = dcount(RemotePort), Hosts = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where Ports > 50 or Hosts > 50
| order by Ports desc
```

Vulnerability scanners and monitoring servers will match — list them as known sources before alerting.

## Detect it

- Detection: [KQL network event hunting](../../detection/kql/network-events.md) — listening ports across the fleet, rare destinations
- Investigate: [Investigate an IP in Splunk](../../tasks/investigation/investigate-ip-splunk.md)
- Hunt: [Lateral movement hunting](../../tasks/threat-hunting/lateral-movement.md)
- Harden: [Windows Defender Firewall CIS baseline](../../tasks/hardening/windows-cis-attack-surface-reduction.md) · [microsegmentation](../networking/microsegmentation.md)

## Related concepts

- [Packet Sniffing](packet-sniffing.md)
- [ARP Spoofing](arp-spoofing.md)
