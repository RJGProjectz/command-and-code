---
title: Wi-Fi Deauthentication and Rogue Access Points
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Threat Hunting, Investigation, Hardening]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, wifi, deauth, evil-twin, rogue-ap, wids]
aliases: [Deauthentication attack, deauth packets, Exploiting Deauthentication Attacks, Aireplay-ng, Airbase-ng, evil twin, rogue access point]
difficulty: intermediate
verified: false
---

# Wi-Fi Deauthentication and Rogue Access Points
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** forged "disconnect" frames knock clients off a real access point, and a rogue or evil-twin access point waits to catch them when they reconnect.

## What it is

Without Protected Management Frames, 802.11 deauthentication and disassociation frames are not authenticated: anyone
can send one claiming to be the AP. Attackers use them to disconnect clients (denial of service), to force a reconnect
so the handshake can be captured ([passphrase attacks](wifi-passphrase-attacks.md)), or to push clients toward an
**evil twin** — a fake AP with the same SSID and a stronger signal. A **rogue AP** is any unauthorised access point
plugged into the network, often by an employee, which bypasses the perimeter.

## How it works

1. **Deauth** — spoofed frames with the AP's BSSID tell one client (or broadcast: all clients) to leave.
2. **Lure** — the client reconnects to the strongest signal with a known SSID, which may be the twin. Open-network
   twins add a captive portal that phishes the Wi-Fi password or corporate credentials.
3. **Exploit** — once connected through the attacker, traffic is in their path ([MITM](man-in-the-middle.md)).

| Defence | What it stops |
| :--- | :--- |
| PMF (802.11w) required | forged deauth/disassoc frames are dropped |
| WPA2/WPA3-Enterprise with server-certificate validation | clients refuse a twin that cannot present the real RADIUS certificate |
| WIDS/WIPS on the controller | detects deauth floods, spoofed BSSIDs, SSIDs from unknown APs; can contain rogues |
| Switch-port 802.1X / NAC | a rogue AP plugged into a wall port does not get network access |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1498](https://attack.mitre.org/techniques/T1498/) Network DoS · [T1557](https://attack.mitre.org/techniques/T1557/) Adversary-in-the-Middle · [T1465](https://attack.mitre.org/techniques/T1465/) Rogue Wi-Fi Access Points (Mobile) |
| **What it leads to** | Wi-Fi outages, credential phishing via captive portal, interception of client traffic |
| **Where defenders meet it** | users reporting "Wi-Fi keeps dropping", WIDS alerts, an SSID seen on a BSSID not in the AP inventory |

## Do it

Survey for unknown access points broadcasting your SSIDs (compare BSSIDs against the AP inventory):

```powershell
# All BSSIDs in range per SSID, with signal and security
netsh wlan show networks mode=bssid
# Disconnect reasons on this client — repeated drops point at deauth or interference
Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational' -MaxEvents 50 |
    Where-Object -Property Id -In -Value 8001, 8002, 8003 |
    Select-Object -Property TimeCreated, Id, Message
```

```bash
# BSSIDs per SSID — a corporate SSID on an unknown BSSID or vendor OUI is a candidate twin
nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list
```

In Wireshark, on a monitor-mode capture **you are authorised to take**, deauthentication frames match
`wlan.fc.type_subtype == 0x0c` and disassociation `0x0a`; dozens per second against one BSSID is an attack, not noise.

## See it

| Source | What you see |
| :--- | :--- |
| WIDS / WIPS (controller, Kismet in IDS mode) | "deauth flood", "spoofed AP MAC", "rogue AP on wire", "SSID impersonation" alerts |
| `WLAN-AutoConfig/Operational` | many 8003 (disconnected) followed by 8001 (connected) on a different BSSID |
| Switch / NAC logs | a new device with an AP vendor OUI on a user port |

## Detect it

- Hunt: compare `netsh wlan show networks mode=bssid` or controller scans against the AP inventory — unknown BSSID with a corporate SSID = evil twin candidate
- Investigate: [Network investigation](../../tasks/investigation/network-investigation.md)
- Harden: [Wi-Fi Security](wifi-security.md) — PMF required, EAP-TLS with server-certificate validation
- Rule: [Wi-Fi disconnect bursts](../../detection/sigma/wlan-events.md#1-disconnect-bursts-deauthentication) and [evil-twin connections](../../detection/sigma/wlan-events.md#2-wlan-autoconfig-connection-analysis-evil-twin)

## Related concepts

- [Wi-Fi Security](wifi-security.md) · [WPA Passphrase Attacks](wifi-passphrase-attacks.md) · [Man-in-the-Middle Attacks](man-in-the-middle.md) · [Denial of Service](denial-of-service.md)
