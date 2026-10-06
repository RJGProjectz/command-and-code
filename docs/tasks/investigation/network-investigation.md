---
title: Network Investigation
type: workflow
platforms: [Windows, Linux, Microsoft Defender, Splunk, SentinelOne]
languages: [PowerShell, Bash, KQL, SPL, S1QL]
tasks: [Investigation, Incident Response, Threat Hunting]
category: Workflow
tags: [workflow, network, connections, dns, firewall, pcap]
aliases: [network investigation, network connections investigation, what is this host talking to, investigate ip]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Network Investigation

**Trigger:** a host communicating with a suspicious IP/domain, unexpected listening service, or anomalous traffic volume.

## 1. Live state on the host

→ Windows [listening](../../platforms/windows/networking.md#find-listening-ports) / [established](../../platforms/windows/networking.md#list-established-connections) · Linux [listening](../../platforms/linux/networking.md#find-listening-ports) / [established](../../platforms/linux/networking.md#list-established-connections)

## 2. Map connections to processes

→ [Windows: process that owns a port](../../platforms/windows/processes.md#find-the-process-that-owns-a-port) · [Linux: process for a port](../../platforms/linux/networking.md#find-the-process-for-a-port)

## 3. Name resolution

What domains did the host resolve? Is `hosts` modified? Is the DNS server the expected one?

→ [Windows DNS cache](../../platforms/windows/networking.md#dns-client-cache) · [DNS servers and hosts file](../../platforms/windows/networking.md#dns-servers-and-hosts-file) · [Linux resolver](../../platforms/linux/networking.md#resolver-configuration)

## 4. History from telemetry

→ [KQL connections to an indicator](../../detection/kql/network-events.md#connections-to-an-indicator) · [KQL DNS](../../detection/kql/network-events.md#dns-queries) · [SPL CIM network traffic](../../detection/spl/network-dns.md#connections-to-an-indicator-cim) · [S1QL network](../../detection/s1ql/hunting.md#network-investigation)

## 5. Other hosts

Which other devices talked to the same destination?

## 6. Firewall / proxy view

Blocked attempts, bytes transferred (exfiltration?), user agent.

## 7. Packet capture (if needed)

→ [tcpdump](../../platforms/linux/networking.md#capture-packets) · Windows: `pktmon` (built-in) or Wireshark

## 8. Contain

→ [Windows firewall block](../../platforms/windows/firewall.md#block-an-ip-during-containment) · [Linux block](../../platforms/linux/networking.md#firewall-rules) · EDR isolation · proxy/DNS sinkhole

## Related

- [Suspicious Outbound Connection](suspicious-outbound-connection.md)
- [Possible Lateral Movement](../threat-hunting/lateral-movement.md)
