---
title: Hash Functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Forensics, Investigation, Threat Intelligence]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, hashing, integrity, sha256]
aliases: [Hash Function, One-Way Hash Functions, Collision Resistance, MD5, SHA-1, SHA-2, SHA-256, SHA-3, BLAKE2b, Blake2, ISOIEC 10118-3]
difficulty: basic
verified: false
---

# Hash Functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a hash function maps any input to a short fixed-size fingerprint that changes completely if one bit changes, and cannot be run backwards.

## What it is

Hashes are the integrity tool of security work: file IOCs, evidence verification, password storage, signatures and
blockchains all rest on them. A cryptographic hash must be:

| Property | Meaning | Broken in |
| :--- | :--- | :--- |
| **Pre-image resistant** (one-way) | from the hash you cannot find the input | — |
| **Second pre-image resistant** | given a file, you cannot make a different file with the same hash | — |
| **Collision resistant** | you cannot find *any* two inputs with the same hash | MD5 (2004), SHA-1 (SHAttered, 2017) |

| Algorithm | Output | Status |
| :--- | :--- | :--- |
| MD5 | 128 bit | collisions trivial — fine for de-duplication, **not** for security |
| SHA-1 | 160 bit | collisions practical — retired for certificates and signatures |
| SHA-2 (SHA-256, SHA-512) | 256/512 bit | current standard; SHA-256 is the default IOC hash |
| SHA-3 (Keccak) | 224–512 bit | different internal design (sponge), a fallback if SHA-2 weakens |
| BLAKE2b / BLAKE2s, BLAKE3 | up to 512 bit | as strong as SHA-3, faster in software; used in Argon2, WireGuard |

ISO/IEC 10118-3 standardises the dedicated hash functions (SHA-2, SHA-3 and others).

## How it works

The input is padded and processed block by block through a compression function (SHA-2: Merkle–Damgård) or absorbed
into a large internal state (SHA-3: sponge). Every output bit depends on every input bit (avalanche effect).

**Passwords are different:** a fast hash lets an attacker test billions of guesses per second. Store passwords with a
slow, salted password hash — Argon2id, scrypt, bcrypt or PBKDF2 — never plain SHA-256 or MD5. Use **HMAC** (hash + secret
key) when you need to prove both integrity and origin.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1110.002](https://attack.mitre.org/techniques/T1110/002/) Password Cracking · [T1550.002](https://attack.mitre.org/techniques/T1550/002/) Pass the Hash · [T1036](https://attack.mitre.org/techniques/T1036/) Masquerading |
| **What it leads to** | weak hashes → cracked passwords, forged certificates (Flame used an MD5 collision), tampered files passing a check |
| **Where defenders meet it** | IOC feeds, evidence chain of custody, software downloads, EDR file reputation |

## Do it

```powershell
# SHA-256 of a file (default algorithm); compare with the vendor's published value
Get-FileHash -Path .\installer.msi
Get-FileHash -Path .\installer.msi -Algorithm SHA512
# Built-in alternative
certutil -hashfile .\installer.msi SHA256
```

```bash
sha256sum suspicious.bin
# Verify a list of known-good hashes (prints OK / FAILED per file)
sha256sum -c SHA256SUMS
openssl dgst -sha3-256 suspicious.bin
b2sum suspicious.bin   # BLAKE2b
```

## See it

| Source | What you see |
| :--- | :--- |
| Sysmon event 1 / 15 | `Hashes=SHA256=...` field when hashing is enabled in the config |
| Defender `DeviceFileEvents` / `DeviceProcessEvents` | `SHA1`, `SHA256`, `MD5` columns for reputation lookups |
| Threat-intel feeds | IOCs as SHA-256 (preferred) or MD5 (legacy) |

## Detect it

- Forensics: [Windows disk artifacts](../../tasks/forensics/windows-disk-artifacts.md) — hash evidence at acquisition
- Hunt: [KQL credential access](../../detection/kql/credential-access.md) — pass-the-hash and NTLM use
- Harden: [Credential dumping](credential-dumping.md) — why NT hashes are worth stealing
- Weak password hashes: [Cryptographic attacks](cryptographic-attacks.md)

## Related concepts

- [Cryptography Fundamentals](cryptography-fundamentals.md) · [Digital Signatures](digital-signatures.md) · [Cryptographic Attacks](cryptographic-attacks.md)
