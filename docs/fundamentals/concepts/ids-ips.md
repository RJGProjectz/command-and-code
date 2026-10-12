---
title: Intrusion Detection and Prevention (IDS/IPS)
type: concept
platforms: [Linux, Windows, Microsoft Defender]
languages: [Bash, KQL]
tasks: [Detection Engineering, Threat Hunting, Hardening]
category: Network Defense
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, ids, ips, nsm]
aliases: [Intrusion Detection Systems, Intrusion Prevention Systems, Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS), How to Implement an IDS-IPS, Network Monitoring and Defense, Suricata, Snort, Zeek]
difficulty: intermediate
verified: false
---

# Intrusion Detection and Prevention (IDS/IPS)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** an IDS watches traffic or hosts and alerts on attacks; an IPS sits inline and blocks them.

## What it is

| | IDS | IPS |
| :--- | :--- | :--- |
| Placement | copy of traffic (SPAN/TAP) or host agent | inline, traffic passes through it |
| Action | alert | drop, reset, alert |
| Risk | missed attack | blocked legitimate traffic |

Network IDS (Suricata, Snort, Zeek) read packets; host IDS (auditd rules, Sysmon + EDR, file-integrity tools) read the
operating system. Detection is **signature-based** (known patterns), **anomaly-based** (deviation from a baseline) or both.

## How it works

1. **Sensor placement** — at the internet edge, between zones, and in front of crown jewels.
2. **Rules** — e.g. a Suricata rule matching a known exploit string, or a Zeek script flagging long DNS names.
3. **Tuning** — suppress noise for your environment; untuned IDS output is ignored within a week.
4. **Forwarding** — send alerts to the [SIEM](siem.md) so they correlate with host and identity logs.

## Why it matters

| | |
| :--- | :--- |
| **Framework** | NIST CSF DE.CM (continuous monitoring) · CIS Control 13 (network monitoring and defense) |
| **What it leads to** | early warning of scans, exploits, C2 beacons and exfiltration |
| **Where defenders meet it** | alert queues, encrypted traffic that sensors cannot read (use TLS metadata and JA3/JA4) |

## Do it

```bash
cc find "network events" ; cc find "dns tunneling"
# Suricata on a lab sensor: test the config, then watch alerts
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo tail -f /var/log/suricata/fast.log
```

## See it

| Source | What you see |
| :--- | :--- |
| Suricata `eve.json` | `event_type: alert` with signature, src/dst, flow id |
| Zeek | `notice.log`, `weird.log`, plus conn/dns/http logs for context |
| Defender for Endpoint | `DeviceNetworkEvents` — the host-side view of the same flow |

## Detect it

- Engineer: [Detection development lifecycle](../../tasks/detection-engineering/detection-development-lifecycle.md), [Alert tuning](../../tasks/detection-engineering/alert-tuning-false-positive-management.md)
- Query: [KQL network events](../../detection/kql/network-events.md), [SPL DNS tunneling](../../detection/spl/dns-tunneling.md)
- Host side: [Sysmon](../systems/sysmon.md), [auditd](../../platforms/linux/auditd.md)

## Related concepts

- [SIEM](siem.md) · [Packet Sniffing](packet-sniffing.md) · [Defense in Depth](defense-in-depth.md)
