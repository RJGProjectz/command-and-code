---
title: Proxy Servers
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Threat Hunting, Administration]
category: Network Defense
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, proxy, c2, web-filtering]
aliases: [Proxy Servers, forward proxy, reverse proxy, SOCKS proxy, web proxy]
difficulty: basic
verified: false
---

# Proxy Servers
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a proxy makes requests on behalf of a client — defenders use it to filter and log web traffic, attackers use it to hide where their traffic comes from.

## What it is

| Type | Sits in front of | Typical use |
| :--- | :--- | :--- |
| Forward proxy | clients | corporate web filtering, logging, TLS inspection |
| Reverse proxy | servers | load balancing, WAF, hiding back-end hosts |
| SOCKS proxy | any TCP app | tunnelling (SSH `-D`), pivoting |
| Anonymising chain | the client's identity | Tor, VPN chains, residential proxy networks |

## How it works

The client connects to the proxy; the proxy opens the real connection and relays data. The server sees the proxy's IP,
not the client's. For HTTPS, a forward proxy either tunnels blindly (`CONNECT`) or inspects with its own trusted
certificate. Attackers chain proxies, compromise routers as relays, or run SOCKS through an implant to reach internal
networks from outside (pivoting).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1090](https://attack.mitre.org/techniques/T1090/) — Proxy (internal, external, multi-hop) |
| **What it leads to** | attacker IPs that geolocate nowhere useful; internal hosts used as stepping stones |
| **Where defenders meet it** | proxy logs (the best web telemetry you have), sign-ins from anonymising networks |

## Do it

```powershell
netsh winhttp show proxy
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object -Property ProxyEnable, ProxyServer
```

```bash
env | grep -i _proxy
ss -tlnp | grep -E ':(1080|3128|8080)\b'   # local listeners on common proxy ports
```

## See it

| Source | What you see |
| :--- | :--- |
| Proxy logs | user, URL, category, bytes — long-lived CONNECT sessions to rare domains |
| Host | unexpected listener on 1080/3128/8080, `ssh -D` or `netsh interface portproxy` rules |
| Identity logs | sign-ins tagged as anonymous / Tor IP |

## Detect it

- Investigate: [Suspicious outbound connection](../../tasks/investigation/suspicious-outbound-connection.md)
- Hunt: [Lateral movement](../../tasks/threat-hunting/lateral-movement.md) — internal pivots
- Rules: [KQL network events](../../detection/kql/network-events.md)

## Related concepts

- [Man-in-the-Middle Attacks](man-in-the-middle.md) · Anonymity and the Dark Web
