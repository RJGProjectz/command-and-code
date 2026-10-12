---
title: Denial of Service (DoS and DDoS)
type: concept
platforms: [Windows, Linux, Azure]
languages: [PowerShell, Bash]
tasks: [Incident Response, Troubleshooting, Hardening]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, dos, ddos, availability]
aliases: [Distributed Denial of Service (DDoS), DoS, DDoS, flooding attack, SYN flood]
difficulty: basic
verified: false
---

# Denial of Service (DoS and DDoS)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** making a service unavailable by exhausting its bandwidth, connections, CPU or memory — from one source (DoS) or many (DDoS).

## What it is

Availability is one leg of the [CIA triad](cia-triad.md). A DoS attack does not need to break in; it only needs to use up
something finite. A DDoS spreads the load over thousands of hijacked devices (a botnet) or abuses open servers that answer
small requests with large replies (amplification), so blocking one IP does not help.

## How it works

| Layer | Example | What runs out |
| :--- | :--- | :--- |
| Volumetric (L3/L4) | UDP / DNS / NTP amplification | upstream bandwidth |
| Protocol (L4) | SYN flood — half-open TCP connections | connection table on server or firewall |
| Application (L7) | HTTP request floods, expensive search queries | web workers, CPU, database |

Defences sit where the resource is: upstream scrubbing (cloud DDoS protection, CDN) for bandwidth, SYN cookies and
connection limits for protocol floods, caching and [rate limiting](../apis/rate-limiting-backoff.md) for application floods.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1498](https://attack.mitre.org/techniques/T1498/) Network DoS · [T1499](https://attack.mitre.org/techniques/T1499/) Endpoint DoS |
| **What it leads to** | outage, ransom demands ("pay or we keep flooding"), cover for a quieter intrusion |
| **Where defenders meet it** | monitoring alerts on latency and error rate, firewall session-table exhaustion |

## Do it

```bash
cc find "high cpu" ; cc find "connections"
```

```bash
# Count half-open connections by source (SYN flood check)
ss -Hnt state syn-recv | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head
sysctl net.ipv4.tcp_syncookies        # 1 = SYN cookies on
```

```powershell
Get-NetTCPConnection -State SynReceived | Group-Object -Property RemoteAddress | Sort-Object -Property Count -Descending | Select-Object -First 10
```

## See it

| Source | What you see |
| :--- | :--- |
| Web / load balancer logs | request rate jumps 10–100x, many 503s, one URL or user agent dominating |
| Firewall | session table near limit, drops from many sources |
| Cloud metrics | Azure DDoS Protection "under attack" metric, inbound packets/s spike |

## Detect it

- Respond: [High CPU troubleshooting](../../tasks/troubleshooting/high-cpu-troubleshooting.md), [Windows connectivity](../../tasks/troubleshooting/windows-connectivity.md)
- Harden: [Kernel tuning (Linux)](../../platforms/linux/kernel-tuning.md), [Azure VNet security](../cloud/azure-vnet-security.md)
- No dedicated rule page yet for flood detection (tracked in WP-31).

## Related concepts

- CIA Triad · [Port Scanning](port-scanning.md)
