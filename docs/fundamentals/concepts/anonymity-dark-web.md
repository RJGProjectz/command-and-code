---
title: Anonymity Networks and the Dark Web (Tor, I2P, Tails)
type: concept
platforms: [Windows, Linux, Microsoft Defender]
languages: [KQL, PowerShell, Bash]
tasks: [Threat Intelligence, Threat Hunting, Investigation]
category: Threat Landscape
security_domain: Intelligence
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, tor, dark-web, anonymity, threat-intel]
aliases: [Anonymity, Anonymity and Pseudonymity, Dark Web, Darknet Markets, Dark Web Hacking Forums, Dark Web Cybersecurity Threats, Dark Web Monitoring Tools, Dark Web Censorship Circumvention, Avoiding Law Enforcement Operations on the Dark Web, Tor Network, Invisible Internet Project, Freenet, Tails, Non-Indexed, Free Speech]
difficulty: intermediate
verified: false
---

# Anonymity Networks and the Dark Web (Tor, I2P, Tails)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** anonymity networks hide who talks to whom; they protect journalists and dissidents and also host criminal markets, so defenders monitor them for their own leaked data and watch for their use inside the network.

## What it is

| Layer | Meaning |
| :--- | :--- |
| Surface web | indexed by search engines |
| Deep web (non-indexed) | not indexed — webmail, intranets, paywalled data; mostly ordinary |
| **Dark web** | reachable only through anonymity software |

**Anonymity** hides identity entirely; **pseudonymity** uses a stable alias that builds reputation (forum handles).

| Network | How it works |
| :--- | :--- |
| **Tor** | onion routing through three relays (guard, middle, exit); `.onion` services never leave the network |
| **I2P** (Invisible Internet Project) | garlic routing, built for services inside the network (eepsites) |
| **Freenet / Hyphanet** | distributed, censorship-resistant data store |
| **Tails** | live OS that routes everything through Tor and forgets everything on shutdown |

Legitimate uses: censorship circumvention and free speech under repressive regimes, journalism and source protection,
private browsing. Criminal uses: **darknet markets** (drugs, stolen data, malware), **hacking forums** (access brokers,
exploit sales), ransomware **leak sites**. Law-enforcement operations (AlphaBay and Hansa 2017, Hydra 2022, Genesis
Market 2023) mostly succeeded through operational-security mistakes, seized servers and cryptocurrency tracing —
anonymity tools do not protect against human error.

## How it works

Defender view:

1. **Monitor** for your organisation's data: leaked credentials, ransomware leak-site listings, access sales naming
   your company (threat-intel providers, breach-notification services).
2. **Control** use inside the network: Tor is rarely needed on corporate endpoints and is common in ransomware and
   C2 tooling — block or alert, with an exception process.
3. **Investigate** safely: dedicated, isolated research environments and legal approval before visiting criminal sites.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1090.003](https://attack.mitre.org/techniques/T1090/003/) Multi-hop Proxy · [T1597](https://attack.mitre.org/techniques/T1597/) Search Closed Sources · [T1567](https://attack.mitre.org/techniques/T1567/) Exfiltration Over Web Service |
| **What it leads to** | C2 over Tor, stolen data for sale, initial access bought from brokers |
| **Where defenders meet it** | Tor traffic alerts, ransomware leak-site notices, credential-leak feeds |

## Do it

```kql
// Tor Browser or tor.exe on endpoints, and connections to typical Tor ports
DeviceProcessEvents
| where FileName =~ "tor.exe" or FolderPath has "Tor Browser"
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
```

```kql
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9050, 9150)
| summarize Connections = count() by DeviceName, InitiatingProcessFileName, RemotePort
```

```bash
# Compare firewall egress logs with the public list of Tor exit addresses
curl -s https://check.torproject.org/torbulkexitlist -o tor_exits.txt
grep -F -f tor_exits.txt /var/log/firewall/egress.log | head
```

## See it

| Source | What you see |
| :--- | :--- |
| EDR process events | `tor.exe`, Tor Browser folders, `obfs4proxy` / pluggable transports |
| Firewall / proxy | connections to known Tor relays; sign-ins from Tor exit IPs in Entra logs |
| Threat-intel feeds | company domain in leaked-credential dumps or leak-site posts |

## Detect it

- Investigate: [Suspicious outbound connection](../../tasks/investigation/suspicious-outbound-connection.md)
- Hunt: [KQL network events](../../detection/kql/network-events.md)
- Intel: [IOC lifecycle and scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) · [Threat actor profiles](../../references/threat-actor-profiles.md)

## Related concepts

- [Proxy Servers](proxy-servers.md) · [OSINT](osint.md) · [Surveillance and Deception](surveillance-deception.md) · [Ransomware](ransomware.md)
