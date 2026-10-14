---
title: Wi-Fi Security (WEP, WPA, WPA2, WPA3)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash, Windows CLI]
tasks: [Hardening, Investigation, Assurance]
category: Network Defense
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, wifi, wireless, wpa2, wpa3, 802.1x]
aliases: [Wireless Security, How to Secure Wireless Networks, Wired Equivalent Privacy (WEP), Wi-Fi Protected Access (WPA), Wi-Fi Protected Access II (WPA2), WPA3, Temporal Key Integrity Protocol (TKIP), Wifi Bands, WEP Cracking, Exploiting WEP, Fake Authentication Attack, ARP Request Replay Attacks, Exploiting ARP Replay Attacks]
difficulty: basic
verified: false
---

# Wi-Fi Security (WEP, WPA, WPA2, WPA3)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** Wi-Fi sends every frame over the air, so its security is only as good as the authentication and encryption mode the access point enforces.

## What it is

Anyone in radio range can receive a wireless frame. Wi-Fi security standards decide who may join and how frames are
encrypted. Each generation fixed the one before:

| Mode | Year | Encryption | Status |
| :--- | :--- | :--- | :--- |
| WEP | 1999 | RC4 with a short, reused IV | **broken** — key recoverable in minutes from captured traffic; never use |
| WPA (TKIP) | 2003 | RC4 + TKIP per-packet keys | stop-gap for WEP hardware; deprecated, disable it |
| WPA2-Personal (PSK) | 2004 | AES-CCMP | sound cipher, but the shared passphrase can be guessed offline (see [WPA passphrase attacks](wifi-passphrase-attacks.md)) |
| WPA2-Enterprise (802.1X) | 2004 | AES-CCMP, per-user keys | each user/device signs in through RADIUS; no shared secret to leak |
| WPA3-Personal (SAE) | 2018 | AES-CCMP/GCMP, SAE handshake | resists offline guessing; forward secrecy |
| WPA3-Enterprise | 2018 | as above, optional 192-bit suite | strongest; requires PMF |

**Bands:** 2.4 GHz reaches further and goes through walls (and leaks further outside the building); 5 GHz and 6 GHz carry
more data over shorter range. 6 GHz (Wi-Fi 6E/7) only allows WPA3 and PMF — a free security upgrade.

## How it works

1. **Discovery** — the AP broadcasts beacons with its SSID and security mode; clients probe for networks they know.
2. **Authentication** — with PSK/SAE both sides prove they know the passphrase; with 802.1X the client signs in to a
   RADIUS server (EAP-TLS with certificates is the strongest choice).
3. **4-way handshake** — both sides derive fresh session keys from the master key; all data frames are then encrypted.
4. **Management frames** — beacons, (de)authentication and disassociation frames are unprotected unless **Protected
   Management Frames (PMF, 802.11w)** are on. Without PMF anyone can forge a "disconnect" frame (see
   [Deauthentication and rogue access points](wifi-deauth-rogue-ap.md)).

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1557](https://attack.mitre.org/techniques/T1557/) Adversary-in-the-Middle · [T1040](https://attack.mitre.org/techniques/T1040/) Network Sniffing · [T1638](https://attack.mitre.org/techniques/T1638/) Adversary-in-the-Middle (Mobile; formerly T1465 Rogue Wi-Fi Access Points) |
| **What it leads to** | an outsider on the internal LAN without touching a cable, traffic capture, a foothold for [MITM](man-in-the-middle.md) |
| **Where defenders meet it** | wireless controller security reports, audit findings ("WEP/TKIP enabled"), unknown SSIDs in a site survey |

## Do it

Secure-by-default checklist for a network you own:

- WPA3-Personal or WPA2/WPA3 transition mode at home; **WPA2/WPA3-Enterprise with EAP-TLS** in an organisation.
- Disable WEP, WPA (TKIP) and **WPS** (its PIN can be brute-forced).
- Turn on **PMF** (required for WPA3, "optional/capable" for mixed networks).
- PSK networks: passphrase of 20+ random characters; rotate when staff leave; separate guest SSID on its own VLAN.
- Patch AP firmware; restrict the admin interface to a management VLAN.

Check what your own client is using:

```powershell
# Authentication and cipher of the current connection
netsh wlan show interfaces
# Every network in range with its security mode (look for Open / WEP / TKIP)
netsh wlan show networks mode=bssid
```

```bash
# SSID, BSSID and security of networks in range (NetworkManager)
nmcli -f SSID,BSSID,CHAN,SECURITY dev wifi list
# Current link details
iw dev wlan0 link
```

## See it

| Source | What you see |
| :--- | :--- |
| `netsh wlan show interfaces` | `Authentication: WPA2-Personal`, `Cipher: CCMP` — anything showing WEP or TKIP needs fixing |
| Windows event log `Microsoft-Windows-WLAN-AutoConfig/Operational` | connect / disconnect / failed-connect events per SSID with the security mode used |
| Wireless controller | per-SSID security settings, client counts per auth type, rogue-AP list |

## Detect it

- Harden: [Windows security baseline](../../tasks/hardening/windows-security-baseline.md) — wireless profile policy via GPO/Intune
- Investigate: [Network investigation](../../tasks/investigation/network-investigation.md)
- Detect: [Deauthentication and rogue access points](wifi-deauth-rogue-ap.md) — WIDS alerts
- Rule: [Wi-Fi detections from WLAN-AutoConfig](../../detection/sigma/wlan-events.md) — disconnect bursts, evil twin, unknown devices

## Related concepts

- [WPA Passphrase Attacks](wifi-passphrase-attacks.md) · [Deauthentication and Rogue APs](wifi-deauth-rogue-ap.md) · [MAC Addresses and Spoofing](mac-address-spoofing.md) · [Packet Sniffing](packet-sniffing.md)
