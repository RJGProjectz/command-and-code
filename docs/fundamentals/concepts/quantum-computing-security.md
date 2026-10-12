---
title: Quantum Computing and Security (Qubits, QKD)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Threat Intelligence, Assurance]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, quantum, cryptography, qkd]
aliases: [Quantum Computing, Quantum Bit, Quantum Algorithm, Quantum Mechanics, Quantum Superposition, Quantum Entanglement, Heisenberg Uncertainty Principle, Quantum Cryptography, Quantum Key Distribution, Quantum Hacking Techniques]
difficulty: intermediate
verified: false
---

# Quantum Computing and Security (Qubits, QKD)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** quantum computers threaten today's public-key crypto, while quantum physics also offers a niche way to distribute keys (QKD) — security teams mostly need to understand the first.

## What it is

| Term | Plain meaning |
| :--- | :--- |
| **Qubit** (quantum bit) | holds a combination of 0 and 1 until measured |
| **Superposition** | many states at once; useful only with algorithms that make wrong answers cancel out |
| **Entanglement** | two qubits whose measurement results are correlated, however far apart |
| **Measurement / uncertainty** | observing a quantum state disturbs it (Heisenberg uncertainty principle, no-cloning theorem) |
| **Quantum algorithm** | Shor's (factoring, discrete logs → breaks RSA/ECC), Grover's (search → halves symmetric key strength) |

Today's machines have too few error-corrected qubits to run Shor's algorithm against real key sizes; estimates of when
that changes vary, which is why migration to [post-quantum cryptography](post-quantum-cryptography.md) starts now.

**Quantum cryptography** usually means **Quantum Key Distribution (QKD)** — e.g. BB84: keys sent as single photons over
fibre; an eavesdropper's measurement disturbs them and shows up as errors. QKD needs dedicated hardware and links, does
not authenticate on its own, and has been attacked through its hardware (**quantum hacking** such as detector blinding).
Agencies like the NSA and the UK NCSC recommend post-quantum algorithms over QKD for most uses.

## How it works

- Shor's algorithm turns factoring into finding the period of a function — quantum computers find periods efficiently.
- Grover's algorithm searches N items in about √N steps, so a 128-bit key gives ~64-bit security: use 256-bit keys.
- QKD security rests on physics, not maths, but every real system adds classical components that can be attacked.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | no technique — strategic risk |
| **What it leads to** | future decryption of recorded traffic, forged signatures on RSA/ECC-based trust chains |
| **Where defenders meet it** | board and regulator questions, vendor "quantum-safe" marketing, crypto-inventory projects |

## Do it

Answer "are we quantum-ready?" with data rather than marketing:

```powershell
# Symmetric strength check: BitLocker volumes should use 256-bit XTS-AES
Get-BitLockerVolume | Select-Object -Property MountPoint, EncryptionMethod
```

```bash
# Does this SSH client negotiate a post-quantum hybrid key exchange?
ssh -v user@server.example.com exit 2>&1 | grep "kex: algorithm"
```

## See it

| Source | What you see |
| :--- | :--- |
| Crypto inventory | count of RSA/ECC keys by system and data lifetime — the quantum exposure |
| Vendor documentation | whether "quantum-safe" means NIST PQC algorithms (good) or proprietary claims |

## Detect it

- Plan: [Post-quantum cryptography](post-quantum-cryptography.md) — migration steps
- No detection rule applies.

## Related concepts

- [Post-Quantum Cryptography](post-quantum-cryptography.md) · [Cryptography Fundamentals](cryptography-fundamentals.md)
