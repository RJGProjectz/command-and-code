---
title: Man-in-the-Middle Attacks
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Threat Hunting, Hardening]
category: Network Attacks
security_domain: Network
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, mitm, adversary-in-the-middle]
aliases: [Man-in-the-middle attacks, MITM, adversary-in-the-middle, AiTM, Post-Connection Attacks, session hijacking]
difficulty: intermediate
verified: false
---

# Man-in-the-Middle Attacks
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** an attacker places themselves between two parties so traffic flows through them, letting them read, change or replay it.

## What it is

Both ends believe they talk directly to each other, but every packet passes a third party. The attacker gets there by
poisoning a lookup (ARP, DNS, DHCP, LLMNR/NBT-NS), by running a rogue access point or proxy, or — for modern phishing —
by relaying a real login page and stealing the session cookie after MFA (AiTM). Once in the path they can sniff, strip
or downgrade encryption, or inject content.

## How it works

1. **Get in the path** — [ARP spoofing](arp-spoofing.md), a rogue DHCP server, a poisoned DNS answer, an [evil-twin Wi-Fi](wifi-deauth-rogue-ap.md)
   network, or a reverse-proxy phishing kit.
2. **Forward traffic** — the victim must keep working, so the attacker relays everything (IP forwarding on).
3. **Exploit the position** — capture credentials from clear-text protocols, relay NTLM, steal session tokens, or offer a
   forged certificate and hope the user clicks through.

Authenticated encryption breaks step 3: TLS with valid certificates, SMB signing, SSH host-key checks and
phishing-resistant MFA (FIDO2) leave the attacker with ciphertext only.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1557](https://attack.mitre.org/techniques/T1557/) — Adversary-in-the-Middle |
| **What it leads to** | credential theft, NTLM relay, session hijack after MFA, data tampering |
| **Where defenders meet it** | certificate warnings, duplicate MAC/IP alerts, sign-ins from a new IP right after a user logged in |

## Do it

```bash
cc find "certificate" ; cc find "LLMNR"
```

Check the things that make MITM work on hosts you own:

```powershell
# Is LLMNR disabled by policy? (1 = disabled)
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue
# Is SMB signing required?
Get-SmbServerConfiguration | Select-Object -Property RequireSecuritySignature, EncryptData
```

```bash
# Who answers for the gateway? More than one MAC = investigate
ip neigh show | sort -k5
```

## See it

| Source | What you see |
| :--- | :--- |
| Browser / client logs | certificate name mismatch or unknown issuer on an internal site |
| Entra ID sign-in logs | same session token used from a second IP and ASN minutes after the real sign-in |
| Switch / DHCP logs | a second DHCP server answering, or one MAC claiming the gateway IP |

## Detect it

- Investigate: [Account compromise](../../tasks/incident-response/account-compromise.md) — AiTM token theft
- Investigate: [Network investigation](../../tasks/investigation/network-investigation.md)
- Harden: [TLS & SSL](../networking/tls-ssl.md), [SMB signing](../smb.md), [Conditional Access](../../platforms/microsoft-365/conditional-access.md)
- No dedicated rule page yet for LLMNR/NBT-NS poisoning (tracked in WP-31).

## Related concepts

- [ARP Spoofing](arp-spoofing.md) · [Packet Sniffing](packet-sniffing.md) · [Proxy Servers](proxy-servers.md)
