---
title: Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Assurance, Administration]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, post-quantum, pqc, kyber, dilithium]
aliases: [Post-Quantum Cryptography (PQC), Quantum-Resistant, NIST Post-Quantum Cryptography Standardization, CRYSTALS-KYBER, CRYSTALS-Dilithium, FALCON, SPHINCS+, Picnic, BIKE, NTRU, SIKE, Supersingular Isogeny Diffie-Hellman, Isogenies, Isogeny-based cryptography, Lattice-based cryptography, Learning With Errors (LWE), Short Integer Solution (SIS), Shortest Vector Problem (SVP), Closest Vector Problem (CVP), Code-based cryptography, Hash-based cryptography, Multivariate polynomial cryptography, Key Encapsulation, Key Decapsulation, "Shor's Algorithm", Non-deterministic Polynomial-time (NP), Non-deterministic Polynomial-time hard (NP-Hard)]
difficulty: advanced
verified: false
---

# Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a large quantum computer running Shor's algorithm would break RSA and elliptic-curve crypto, so new algorithms built on different hard problems are replacing them now.

## What it is

RSA, Diffie-Hellman and ECC are safe because factoring and discrete logarithms are hard for classical computers.
**Shor's algorithm** solves both efficiently on a large fault-tolerant quantum computer. Symmetric crypto and hashes only
lose about half their strength (Grover's algorithm), so AES-256 and SHA-384+ remain fine.

The urgent risk is **harvest now, decrypt later**: traffic recorded today can be decrypted once such a machine exists.
Long-lived secrets therefore need quantum-resistant key exchange first; signatures follow.

**NIST standards (2024):**

| Standard | Was | Type | Hard problem |
| :--- | :--- | :--- | :--- |
| FIPS 203 **ML-KEM** | CRYSTALS-Kyber | key encapsulation (KEM) | Module Learning With Errors (lattice) |
| FIPS 204 **ML-DSA** | CRYSTALS-Dilithium | signature | Module LWE / SIS (lattice) |
| FIPS 205 **SLH-DSA** | SPHINCS+ | signature | hash functions only (stateless hash-based) |
| FN-DSA (draft FIPS 206) | FALCON | signature (small) | NTRU lattices |
| HQC (selected 2025) | — | backup KEM | error-correcting codes (code-based) |

Families and candidates you will see named: **lattice-based** (LWE, SIS; the underlying Shortest/Closest Vector
Problems are NP-hard in their exact forms), **code-based** (Classic McEliece, BIKE, HQC), **hash-based** (SPHINCS+, XMSS,
LMS), **multivariate polynomial** (Rainbow — broken 2022), **isogeny-based** (SIKE/SIDH — broken classically in 2022),
symmetric-primitive signatures (Picnic — not selected), and NTRU (finalist, not standardised as a KEM).

## How it works

A **KEM** replaces classic key exchange: the sender *encapsulates* — generates a random shared secret and a ciphertext
using the recipient's public key; the recipient *decapsulates* the ciphertext with the private key to get the same
secret, which then keys AES. Deployments run **hybrid** (classical X25519 + ML-KEM together) so a flaw in either one
alone does not break the session.

Migration plan:

1. **Inventory** where public-key crypto lives: TLS endpoints, VPNs, SSH, code-signing, PKI, HSMs, firmware.
2. **Prioritise** data that must stay secret for 10+ years and systems with long replacement cycles.
3. **Enable hybrid key exchange** where products support it (browsers and OpenSSH already do).
4. **Plan PKI and signature migration** once vendors and CAs support ML-DSA / SLH-DSA; keep crypto-agility in mind.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | no technique — strategic risk; collection relates to [T1040](https://attack.mitre.org/techniques/T1040/) Network Sniffing |
| **What it leads to** | retroactive decryption of recorded VPN/TLS traffic; forged signatures once RSA/ECC fall |
| **Where defenders meet it** | regulator deadlines (e.g. US NSM-10 / CNSA 2.0 timelines), vendor roadmaps, crypto inventories |

## Do it

```bash
# Key-exchange algorithms your OpenSSH supports (mlkem768x25519 / sntrup761x25519 = post-quantum hybrid)
ssh -Q kex
# KEMs and signature algorithms in your OpenSSL (ML-KEM / ML-DSA appear from OpenSSL 3.5)
openssl list -kem-algorithms
openssl list -signature-algorithms | grep -iE "ml-dsa|slh-dsa"
```

```powershell
# Start the inventory: certificates and their public-key algorithm in the machine store
Get-ChildItem -Path Cert:\LocalMachine\My |
    Select-Object -Property Subject, NotAfter, @{Name = 'KeyAlgorithm'; Expression = { $_.PublicKey.Oid.FriendlyName } }
```

## See it

| Source | What you see |
| :--- | :--- |
| `ssh -v` output | `kex: algorithm: mlkem768x25519-sha256` (or `sntrup761x25519`) on a hybrid connection |
| Browser dev tools → Security | key exchange `X25519MLKEM768` on sites that support hybrid PQ TLS |
| Certificate inventory | RSA/ECDSA keys and expiry dates — the backlog for signature migration |

## Detect it

- Harden: [SSH keys](../identity/ssh-keys.md) · [TLS & SSL](../networking/tls-ssl.md) · [PKI](../identity/pki.md)
- Background: [Quantum computing and security](quantum-computing-security.md)
- No detection rule applies; track progress as an assurance metric (share of endpoints negotiating hybrid key exchange).

## Related concepts

- [Quantum Computing and Security](quantum-computing-security.md) · [Cryptography Fundamentals](cryptography-fundamentals.md) · [Digital Signatures](digital-signatures.md)
