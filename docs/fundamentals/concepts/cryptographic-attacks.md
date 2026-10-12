---
title: Cryptographic Attacks and Cryptanalysis
type: concept
platforms: [Windows, Linux, Microsoft Defender]
languages: [PowerShell, Bash, KQL]
tasks: [Threat Hunting, Hardening, Assurance]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, cryptanalysis, weak-ciphers, downgrade]
aliases: [Cryptanalysis, Cryptographic Attacks]
difficulty: intermediate
verified: false
---

# Cryptographic Attacks and Cryptanalysis
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** real-world attacks rarely break the maths — they exploit short keys, weak or legacy algorithms, downgrades, bad randomness and implementation leaks.

## What it is

Cryptanalysis is the study of breaking ciphers. Modern algorithms (AES, SHA-2, ECDHE) have no practical break; what fails
is how they are chosen, configured and implemented.

| Attack class | Example | Fix |
| :--- | :--- | :--- |
| Brute force / dictionary | offline guessing of password hashes, Kerberos tickets, Wi-Fi handshakes | long secrets, slow salted hashes, AES-only Kerberos |
| Weak algorithm | RC4 Kerberos tickets ([Kerberoasting](kerberoasting.md)), MD5/SHA-1 collisions, DES/3DES | disable legacy algorithms |
| Downgrade | POODLE (SSL 3.0), FREAK and Logjam (export-grade keys) | TLS 1.2+ only, no export/anon suites |
| Padding oracle / chosen-ciphertext | CBC padding errors leaking plaintext | AEAD modes (GCM, ChaCha20-Poly1305) |
| Bad randomness / nonce reuse | repeated ECDSA nonce, GCM nonce reuse, predictable keys | vetted libraries, CSPRNG |
| Side channel | timing, power, cache (Spectre-class) leaks of keys | constant-time code, HSMs |
| Birthday / collision | forged certificates with MD5 | SHA-256+ |
| Store now, decrypt later | recorded traffic decrypted by a future quantum computer | [post-quantum key exchange](post-quantum-cryptography.md) |

## How it works

Attackers look for the weakest link an endpoint will still accept: a server that still offers TLS 1.0, a service
account that still issues RC4 tickets, a password hashed with unsalted MD5. Defence is mostly **inventory and
removal** of legacy options, then monitoring for anyone still using them.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1600](https://attack.mitre.org/techniques/T1600/) Weaken Encryption · [T1558.003](https://attack.mitre.org/techniques/T1558/003/) Kerberoasting · [T1110.002](https://attack.mitre.org/techniques/T1110/002/) Password Cracking |
| **What it leads to** | cracked service-account passwords, decrypted sessions, forged certificates |
| **Where defenders meet it** | vulnerability scans ("weak cipher suites"), RC4 ticket requests in DC logs, compliance audits |

## Do it

Inventory weak crypto on systems you own:

```powershell
# TLS cipher suites enabled on this Windows host
Get-TlsCipherSuite | Select-Object -Property Name, Exchange, Cipher, CipherLength
# Legacy SCHANNEL protocols explicitly enabled/disabled
Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Recurse -ErrorAction SilentlyContinue
# Service accounts allowed RC4 (msDS-SupportedEncryptionTypes without AES bits 0x18)
Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties msDS-SupportedEncryptionTypes |
    Select-Object -Property SamAccountName, msDS-SupportedEncryptionTypes
```

```bash
# Will my server still accept TLS 1.0 / 1.1? (a handshake = yes)
openssl s_client -connect intranet.example.com:443 -tls1_1 </dev/null
# Full cipher inventory of a host you are authorised to scan
nmap --script ssl-enum-ciphers -p 443 intranet.example.com
```

## See it

| Source | What you see |
| :--- | :--- |
| Security event 4769 on DCs | `Ticket Encryption Type 0x17` (RC4) — Kerberoasting or a legacy service |
| Security event 4768 | TGTs issued with RC4 or DES |
| Web/proxy and load-balancer logs | negotiated protocol `TLSv1`/`TLSv1.1`, cipher names with `RC4`, `3DES`, `CBC` |

## Detect it

```kql
// RC4-encrypted service tickets (Kerberoasting or legacy service)
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$" and ServiceName != "krbtgt"
| summarize Tickets = count(), Services = make_set(ServiceName, 20) by TargetUserName, IpAddress
```

- Hunt: [Kerberoasting](kerberoasting.md) · [KQL credential access](../../detection/kql/credential-access.md)
- Harden: [AD Kerberos & LDAP hardening](../../tasks/hardening/ad-kerberos-ldap-hardening.md) · [TLS & SSL](../networking/tls-ssl.md)

## Related concepts

- [Cryptography Fundamentals](cryptography-fundamentals.md) · [Hash Functions](hash-functions.md) · [WPA Passphrase Attacks](wifi-passphrase-attacks.md) · [Post-Quantum Cryptography](post-quantum-cryptography.md)
