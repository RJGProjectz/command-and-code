---
title: WPA/WPA2 Passphrase Attacks (Handshake Capture)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Investigation, Threat Hunting]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, wifi, wpa2, password-cracking, handshake]
aliases: ["Hacking WPA & WPA2", WPA and WPA2 Cracking, "Quick Guide for Hacking WPA & WPA2", Capturing the Handshake, WPA handshake, PMKID, Cracking WPA and WPA2 Wi-Fi with Wifite, Wifite, Aircrack-ng, Airodump-ng, Airodump-ng Packet Sniffing, Airdecap-ng, Change MAC from Managed to Monitor Mode, Wireless Network Hacking, Pre-Connection Network Attacks]
difficulty: intermediate
verified: false
---

# WPA/WPA2 Passphrase Attacks (Handshake Capture)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a WPA/WPA2-Personal handshake recorded over the air lets an attacker guess the shared passphrase offline, at full GPU speed, without the network ever noticing.

## What it is

WPA2-Personal derives every session key from one shared passphrase plus the SSID. The 4-way handshake (or, on many
APs, a single PMKID value in the first frame) contains enough material to test a guess: take a candidate passphrase,
derive the key, see if it matches. That test runs **offline**, so there is no lockout and no log entry on the AP.
Passive capture works from a car park with a directional antenna; tools in the Aircrack-ng suite, Wifite or hcxtools
automate it, and wordlists plus GPU crackers do the guessing.

The cipher (AES) is not broken — the **passphrase** is the weak point.

## How it works

1. **Listen** — a wireless card in monitor mode records frames on the AP's channel (pre-connection: no need to join).
2. **Get a handshake** — wait for a client to join, or force one to reconnect with a forged deauthentication frame
   (see [Deauthentication and rogue APs](wifi-deauth-rogue-ap.md)); PMKID needs no client at all.
3. **Guess offline** — try wordlist entries and rules against the captured material until one matches.
4. **Join or decrypt** — with the passphrase the attacker can join the network and decrypt captured traffic of other
   PSK clients.

What stops each step:

| Step | Defence |
| :--- | :--- |
| Force a reconnect | PMF (802.11w) makes forged deauth frames invalid |
| Guess offline | WPA3-SAE — every guess needs a live exchange with the AP; offline guessing is impossible |
| Guess offline (WPA2) | long random passphrase (20+ characters) puts it beyond any wordlist |
| Shared secret at all | WPA2/WPA3-Enterprise (802.1X, EAP-TLS): no passphrase, per-user keys, revocable certificates |

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1040](https://attack.mitre.org/techniques/T1040/) Network Sniffing · [T1110.002](https://attack.mitre.org/techniques/T1110/002/) Password Cracking |
| **What it leads to** | network access from outside the building, decryption of other clients' traffic, pivot to [MITM](man-in-the-middle.md) |
| **Where defenders meet it** | WIDS deauth-flood alerts just before a capture, unknown client MACs on the corporate SSID, pentest reports |

## Do it

Assess your **own** PSK networks without attacking them:

```powershell
# Which security mode and cipher is this SSID really using?
netsh wlan show interfaces
# Saved Wi-Fi profiles on this machine — PSK profiles carry a shared secret that leaves with the laptop
netsh wlan show profiles
```

```bash
# Is WPA3 (SAE) or PMF offered by the access points around you?
nmcli -f SSID,SECURITY dev wifi list | grep -E "SAE|WPA3|WPA2"
```

- Replace guessable PSKs (company name + year, street address) with a random 20+ character passphrase.
- Move staff devices to 802.1X; keep PSK only for guest/IoT on isolated VLANs.
- Enable PMF and WPA3 or transition mode where the clients support it.

## See it

| Source | What you see |
| :--- | :--- |
| WIDS / wireless controller | burst of deauthentication frames against one client, then that client reconnects — classic handshake capture |
| Controller client list | a new MAC authenticated with the PSK that does not match any known asset |
| DHCP / NAC logs | unknown hostname or vendor OUI receiving a lease on the staff SSID |

Passive capture alone is invisible; detection depends on the active steps (deauth) and on the attacker later joining.

## Detect it

- Detect: [Deauthentication and rogue access points](wifi-deauth-rogue-ap.md) — WIDS deauth alerts
- Investigate: [Network investigation](../../tasks/investigation/network-investigation.md) — new devices on the WLAN
- Harden: [Wi-Fi Security](wifi-security.md) — WPA3, 802.1X, PMF
- No dedicated rule page yet for unknown-device-on-WLAN (tracked in WP-31).

## Related concepts

- [Wi-Fi Security](wifi-security.md) · [Deauthentication and Rogue APs](wifi-deauth-rogue-ap.md) · [Packet Sniffing](packet-sniffing.md) · [MAC Addresses and Spoofing](mac-address-spoofing.md)
