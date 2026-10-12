---
title: OSI Model and TCP
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Troubleshooting, Investigation]
category: Networking Fundamentals
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, osi, tcp, protocols]
aliases: [OSI Model, Transmission Control Protocol (TCP), TCP Message Types, TCP flags, three-way handshake, Protocol Security, Fundamentals of Network Security, Network Security]
difficulty: basic
verified: false
---

# OSI Model and TCP
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** the OSI model splits networking into seven layers so you can say *where* a problem or attack lives; TCP is the layer-4 protocol that gives reliable, ordered connections.

## What it is

| # | Layer | Examples | Typical attack / control |
| ---: | :--- | :--- | :--- |
| 7 | Application | HTTP, DNS, SMTP | SQL injection, WAF |
| 6 | Presentation | TLS encoding, compression | downgrade attacks |
| 5 | Session | sessions, RPC | session hijack |
| 4 | Transport | TCP, UDP | SYN flood, port scan, firewall rules |
| 3 | Network | IP, ICMP | IP spoofing, routing ACLs |
| 2 | Data link | Ethernet, Wi-Fi, ARP | ARP spoofing, 802.1X |
| 1 | Physical | cable, radio | jamming, rogue device |

Network security means putting a control at each layer that matters to you — defence in depth, not one firewall.

## How it works — TCP message types

TCP segments carry flags. The useful ones to recognise:

| Flag | Meaning |
| :--- | :--- |
| SYN | open a connection |
| SYN-ACK | server accepts |
| ACK | acknowledge data |
| PSH | deliver now |
| FIN | close gracefully |
| RST | abort / port closed |

Connection setup is the three-way handshake **SYN → SYN-ACK → ACK**. A port scanner that sends SYN and never finishes,
or a host that answers everything with RST, shows up clearly once you know this pattern.

## Why it matters

| | |
| :--- | :--- |
| **Framework** | NIST CSF PR.IR (infrastructure resilience) · CIS Control 12 (network infrastructure) |
| **What it leads to** | faster troubleshooting ("which layer breaks?"), better firewall and detection logic |
| **Where defenders meet it** | packet captures, firewall logs, connection-state tables |

## Do it

```powershell
Test-NetConnection -ComputerName example.com -Port 443 -InformationLevel Detailed
Get-NetTCPConnection -State Established | Select-Object -First 10
```

```bash
ss -tan state established | head
sudo tcpdump -nn -c 20 'tcp[tcpflags] & (tcp-syn|tcp-rst) != 0'
```

## See it

| Source | What you see |
| :--- | :--- |
| Packet capture | the handshake, retransmissions, RST storms |
| Firewall logs | allowed / dropped by layer-3/4 tuple |
| Zeek `conn.log` | connection state codes (S0 = SYN no reply, REJ = RST) |

## Detect it

- Troubleshoot: [Windows connectivity](../../tasks/troubleshooting/windows-connectivity.md), [SSH connection timeout](../../tasks/troubleshooting/ssh-connection-timeout-troubleshooting.md)
- Inspect: [Linux networking](../../platforms/linux/networking.md), [Windows networking](../../platforms/windows/networking.md)
- Query: [KQL network events](../../detection/kql/network-events.md)

## Related concepts

- [Port Scanning](port-scanning.md) · [Packet Sniffing](packet-sniffing.md) · [Defense in Depth](defense-in-depth.md)
