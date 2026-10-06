---
title: Suspicious Outbound Connection
type: workflow
platforms: [Windows, Linux, Microsoft Defender, Splunk]
languages: [PowerShell, Bash, KQL, SPL]
tasks: [Investigation, Incident Response, Threat Hunting]
category: Workflow
tags: [workflow, c2, beaconing, outbound, exfiltration, threat intel]
aliases: [suspicious outbound connection, c2 alert, beaconing alert, connection to malicious ip, outbound to bad domain]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Suspicious Outbound Connection

**Trigger:** connection to a threat-intel indicator, beaconing alert, or unusual destination from a server.

## 1. Which process made the connection?

The process tells you more than the IP.

→ [KQL scripting engines with external connections](../../detection/kql/network-events.md#scripting-engines-making-external-connections) · Live: [Windows](../../platforms/windows/networking.md#list-established-connections), [Linux](../../platforms/linux/networking.md#list-established-connections)

## 2. Validate the indicator

Age and source of the intel, shared hosting/CDN (one IP, thousands of sites), ASN, first-seen in your environment.

## 3. Look at timing and volume

Regular intervals → beaconing. Large outbound volume → exfiltration. Single connection → may be a one-off (ad, redirect).

→ [KQL possible beaconing](../../detection/kql/network-events.md#possible-beaconing) · [SPL interval regularity](../../detection/spl/network-dns.md#beaconing-by-interval-regularity)

## 4. Investigate the process

→ [Suspicious Process](../incident-response/suspicious-process.md) · [Suspicious PowerShell](../incident-response/suspicious-powershell.md)

## 5. Scope

All hosts contacting the destination; all destinations contacted by the same process hash.

→ [KQL rare external destinations](../../detection/kql/network-events.md#rare-external-destinations) · [S1QL connections to an indicator](../../detection/s1ql/hunting.md#connections-to-an-indicator)

## 6. Contain

Isolate confirmed hosts; block domain/IP at DNS, proxy, firewall and EDR indicators.

→ [Windows firewall block](../../platforms/windows/firewall.md#block-an-ip-during-containment) · [Defender indicators](../../platforms/microsoft-365/defender.md#indicators)
