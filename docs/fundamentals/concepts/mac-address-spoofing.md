---
title: MAC Addresses and Spoofing
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Hardening, Troubleshooting]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, mac-address, layer-2, nac]
aliases: [MAC address, data link layer, How to Change Your MAC Address, MAC spoofing, Network Access Control (NAC), 802.1X]
difficulty: basic
verified: false
---

# MAC Addresses and Spoofing
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a MAC address is the hardware address used on the local link (OSI layer 2); because software can change it, it identifies a device but never proves who it is.

## What it is

Every network interface has a 48-bit MAC address, for example `00:1A:2B:3C:4D:5E`. The first half names the vendor (OUI).
Switches forward frames by MAC, DHCP hands out leases by MAC, and many networks allow or block devices by MAC. Changing it
is a normal driver setting — phones randomise it for privacy — so MAC filtering alone is weak access control.

**Network Access Control (NAC)** fixes that by making the device authenticate before the switch port or Wi-Fi opens:
802.1X with a certificate or credential, optionally plus a health check.

## How it works

1. The data link layer wraps IP packets in frames addressed MAC-to-MAC; ARP maps IP to MAC ([ARP spoofing](arp-spoofing.md)).
2. An attacker copies the MAC of an allowed device (printer, phone) to pass a MAC filter or a captive portal.
3. Port security (max MACs per port), DHCP snooping and 802.1X stop the copy from being useful.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | used inside [T1557](https://attack.mitre.org/techniques/T1557/) AiTM and [T1200](https://attack.mitre.org/techniques/T1200/) Hardware Additions |
| **What it leads to** | bypass of MAC filters and captive portals, confusing asset inventory and DHCP logs |
| **Where defenders meet it** | one MAC on two switch ports, a vendor OUI that does not match the device type |

## Do it

```powershell
Get-NetAdapter | Select-Object -Property Name, MacAddress, Status
Get-NetNeighbor -AddressFamily IPv4 | Where-Object -Property State -NE 'Unreachable'
```

```bash
ip -br link            # interface and MAC
ip neigh show          # IP-to-MAC table
```

To test your own NAC in a lab, change a lab NIC's address (`ip link set dev eth0 address 02:00:00:00:00:01` or the
adapter's *Network Address* property) and confirm the port still demands 802.1X.

## See it

| Source | What you see |
| :--- | :--- |
| Switch logs | MAC flapping between ports, port-security violation |
| DHCP server | one MAC requesting leases with different host names |
| NAC / RADIUS | 802.1X failures followed by MAC Authentication Bypass success |

## Detect it

- Inspect: [Network adapter and IP configuration](../../tasks/administration/network-adapter-ip-configuration.md), [DHCP](../networking/dhcp.md)
- Investigate: [Network investigation](../../tasks/investigation/network-investigation.md)
- Harden: [Microsegmentation](../networking/microsegmentation.md)

## Related concepts

- [OSI Model and TCP](osi-model-tcp.md) · [ARP Spoofing](arp-spoofing.md) · [Wi-Fi Security](wifi-security.md)
