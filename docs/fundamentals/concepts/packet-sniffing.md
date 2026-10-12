---
title: Packet Sniffing
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Troubleshooting, Threat Hunting]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-11
last_updated: 2026-10-11
tags: [concept, pcap, sniffing, tcpdump, wireshark]
aliases: [network sniffing, packet capture, Wireshark, tcpdump, pktmon, promiscuous mode]
difficulty: basic
verified: false
---

# Packet Sniffing
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** recording the packets that pass a network interface — a core troubleshooting skill and an attacker's way to steal what is sent in clear text.

## What it is

A network card normally hands the operating system only frames addressed to it. A sniffer (Wireshark, tcpdump,
Windows `pktmon`) captures everything the interface sees, sometimes in *promiscuous mode* so it keeps frames for other
hosts too. Defenders use it to prove what is on the wire; attackers use it to collect passwords, cookies and hashes from
unencrypted protocols.

## How it works

1. Capture point: the sniffer sees only what reaches its interface — its own traffic, broadcasts, a switch mirror (SPAN)
   port, or traffic redirected by [ARP spoofing](arp-spoofing.md).
2. Capture: a driver copies frames into a buffer; a filter (BPF, e.g. `port 53`) keeps the volume down.
3. Analysis: the capture file (`.pcap` / `.pcapng` / `.etl`) is decoded protocol by protocol.

Encryption (TLS, SSH, SMB signing and encryption, Kerberos) limits what a sniffer can read, but metadata — who talks to
whom, when and how much — stays visible.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1040](https://attack.mitre.org/techniques/T1040/) — Network Sniffing |
| **What it leads to** | captured credentials, session tokens, discovery of internal hosts and services |
| **Where defenders meet it** | a capture tool installed on a server that has no reason for it; an interface in promiscuous mode |

## Do it

```bash
cc find "packet capture"
cc view docs/tasks/investigation/network-investigation.md
```

Capture on a host you own, with a filter and a size limit:

```bash
sudo tcpdump -i eth0 -nn -c 500 -w /tmp/capture.pcap 'port 53 or port 443'
```

```powershell
# Built-in Windows capture (no install), then convert for Wireshark
pktmon start --capture --pkt-size 0 --file-name C:\Temp\capture.etl
pktmon stop
pktmon etl2pcap C:\Temp\capture.etl --out C:\Temp\capture.pcapng
```

## See it

Signs that someone is sniffing on a host:

```powershell
Get-NetAdapter | Select-Object -Property Name, Status, PromiscuousMode
Get-Process -Name Wireshark, dumpcap, tshark, windump -ErrorAction SilentlyContinue
```

```bash
ip -d link show | grep -B1 -i promisc
pgrep -a 'tcpdump|tshark|dumpcap'
```

| Source | What you see |
| :--- | :--- |
| Process telemetry (Sysmon 1 / 4688) | `tcpdump`, `dumpcap`, `pktmon start` run outside a change window |
| Linux kernel log | `device eth0 entered promiscuous mode` |
| Software inventory | Npcap / WinPcap driver installed on a server |

## Detect it

- Investigate: [Network Investigation — packet capture step](../../tasks/investigation/network-investigation.md)
- Inspect: [Linux networking and DNS](../../platforms/linux/networking.md)
- Hunt: [LOLBins execution hunting](../../tasks/threat-hunting/lolbins-execution-hunting.md) — capture tools run like any other unexpected binary
- Harden: encrypt in transit — [TLS & SSL](../networking/tls-ssl.md), [SMB signing](../smb.md)
- No dedicated rule page yet for capture-tool execution.

## Related concepts

- [ARP Spoofing](arp-spoofing.md)
- [Port Scanning](port-scanning.md)
