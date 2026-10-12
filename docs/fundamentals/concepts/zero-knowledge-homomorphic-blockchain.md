---
title: Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Threat Intelligence, Investigation]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, zero-knowledge, blockchain, homomorphic-encryption]
aliases: [Zero-Knowledge, Zero-knowledge Proofs, Zero Knowledge Proof-based cryptography, Zero-Knowledge Proofs and the Future of Cryptocurrency, zk-SNARKs, zK-STARKs, ZK-Rollups, "Rollups (Optimistic Rollups, ZK-Rollups)", Homomorphic Encryption, Fully Homomorphic Encryption (FHE), ISOIEC 18033-6, Blockchain Technology, Blockchain and Cryptography, Decentralized Ledgers]
difficulty: advanced
verified: false
---

# Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** zero-knowledge proofs show a statement is true without revealing the secret, homomorphic encryption computes on data while it stays encrypted, and blockchains chain hashes and signatures into a shared tamper-evident ledger.

## What it is

**Zero-knowledge proofs (ZKPs).** A prover convinces a verifier that they know something (a password, that a
transaction is valid) without revealing it. **zk-SNARKs** are tiny and fast to verify but many need a trusted setup;
**zk-STARKs** need no trusted setup and rely only on hash functions (so they are considered post-quantum), at the cost of
larger proofs. Uses: privacy coins, identity ("over 18" without showing a birth date), passwordless protocols.

**Homomorphic encryption (HE).** Partially homomorphic schemes allow one operation on ciphertext (RSA: multiply; Paillier:
add — ISO/IEC 18033-6). **Fully homomorphic encryption (FHE)**, first shown in 2009, allows any computation, so a cloud
can process data it cannot read. Still far slower than plaintext; used in niche privacy analytics.

**Blockchain / decentralised ledgers.** Each block contains the hash of the previous one ([hash functions](hash-functions.md)),
transactions are authorised with [digital signatures](digital-signatures.md) (Bitcoin and Ethereum use ECDSA on
secp256k1), and a consensus mechanism (proof of work / stake) decides which chain is valid. **Rollups** batch many
transactions off-chain and post a summary: *optimistic* rollups assume validity and allow a fraud-proof challenge
window; *ZK-rollups* post a validity proof (SNARK/STARK).

## How it works

- ZKP: interactive challenge-response, or non-interactive proofs where a hash replaces the verifier's random challenge.
- FHE: noise-based lattice schemes (related to [post-quantum](post-quantum-cryptography.md) LWE) with periodic "bootstrapping"
  to keep noise under control.
- Blockchain security fails at the edges: stolen private keys, malicious smart contracts, compromised bridges and
  exchanges, phishing for seed phrases — not at the hash chain.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1496](https://attack.mitre.org/techniques/T1496/) Resource Hijacking (cryptomining) · [T1657](https://attack.mitre.org/techniques/T1657/) Financial Theft |
| **What it leads to** | cryptojacking on servers and cloud accounts, ransomware payments, wallet and seed-phrase theft |
| **Where defenders meet it** | CPU spikes and mining-pool connections, crypto-wallet addresses in ransom notes, blockchain analysis in IR |

## Do it

See why a hash chain is tamper-evident (illustration only):

```powershell
$prev = '0' * 64
foreach ($data in 'tx: A->B 5', 'tx: B->C 2') {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($prev + $data)
    $prev = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
    "{0}  {1}" -f $prev.Substring(0, 16), $data
}
# Change the first transaction and every later hash changes
```

```bash
# Hunt for cryptominers on a Linux host: high-CPU processes and their connections
ps -eo pid,user,%cpu,cmd --sort=-%cpu | head -n 5
ss -tnp | grep -E ":(3333|4444|5555|7777|14444)\b"
```

## See it

| Source | What you see |
| :--- | :--- |
| EDR / Defender | `xmrig`-like binaries, `stratum+tcp://` in command lines, sustained 100 % CPU |
| DNS / proxy logs | lookups of mining pools or wallet/exchange domains from servers |
| Ransom notes / IR | wallet addresses to trace with blockchain analysis tools |

## Detect it

- Investigate: [Suspicious outbound connection](../../tasks/investigation/suspicious-outbound-connection.md) — mining-pool traffic
- Background: [Ransomware](ransomware.md) — payments in cryptocurrency
- No dedicated cryptomining rule page yet (tracked in WP-31).

## Related concepts

- [Hash Functions](hash-functions.md) · [Digital Signatures](digital-signatures.md) · [Post-Quantum Cryptography](post-quantum-cryptography.md)
