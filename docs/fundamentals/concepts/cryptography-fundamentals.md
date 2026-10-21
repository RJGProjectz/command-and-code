---
title: Cryptography Fundamentals (Symmetric and Asymmetric Encryption)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Hardening, Assurance, Administration]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, encryption, aes, rsa, key-management]
aliases: [Cryptography, Introduction to Cryptography, Cryptology, Cryptographic Algorithms, Cryptographic Security, Cryptographic Protocols, Cryptography in Applications, Encryption, Encryption Tools, Encryption in Network Security, Data Protection Techniques, Symmetric Cryptography, Symmetric vs. Asymmetric Encryption, Asymmetric Encryption, Advanced Encryption Standard (AES), Data Encryption Standard, Triple DES, RSA, Elliptic Curve Cryptography, Algorithm, FIPS 140-2, NIST Special Publication 800-38A, NIST Special Publication 800-56B, NIST Special Publication 800-56C, NIST Special Publication 800-57, NIST Special Publication 800-175B, ISOIEC 18033-2, ISOIEC 18033-3, ISOIEC 19772, ISOIEC 29192-3]
difficulty: basic
verified: false
---

# Cryptography Fundamentals (Symmetric and Asymmetric Encryption)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** encryption turns readable data into ciphertext that only a key holder can reverse — symmetric ciphers do the bulk work, asymmetric ones solve key exchange and identity.

## What it is

Cryptography protects **confidentiality** (only the right people read it), **integrity** (nobody changed it — see
[hash functions](hash-functions.md)) and **authenticity** (it really came from the sender — see
[digital signatures](digital-signatures.md)). Cryptology is the umbrella term: cryptography builds the systems,
[cryptanalysis](cryptographic-attacks.md) tries to break them.

| Family | How keys work | Examples | Use today |
| :--- | :--- | :--- | :--- |
| **Symmetric** | one shared secret key encrypts and decrypts; fast | AES-128/256 (block), ChaCha20 (stream) | disk encryption, VPN and TLS bulk traffic |
| Legacy symmetric | | DES (56-bit key, brute-forced in 1998), 3DES (64-bit blocks, Sweet32) | **retire** — NIST disallows both for encryption |
| **Asymmetric** | public key encrypts/verifies, private key decrypts/signs; slow | RSA (2048+ bits), elliptic curves (P-256, X25519, Ed25519) | key exchange, certificates, signatures |

Real protocols are **hybrid**: TLS, SSH, PGP and S/MIME use asymmetric crypto to agree on or wrap a random symmetric key,
then AES or ChaCha20 encrypts the data.

**Modes matter.** A block cipher needs a mode of operation (NIST SP 800-38A: ECB, CBC, CTR…). ECB leaks patterns and
should never be used; modern code uses **authenticated encryption** (AES-GCM, ChaCha20-Poly1305 — ISO/IEC 19772), which
detects tampering as well as hiding data.

## How it works

1. **Generate** a key from a cryptographically secure random source — never a password directly (use a KDF such as
   PBKDF2, scrypt or Argon2).
2. **Exchange or wrap** it: Diffie-Hellman / ECDHE agrees a key over an open network; RSA-OAEP or a KEM wraps it for one
   recipient (NIST SP 800-56B/56C).
3. **Encrypt** with an AEAD cipher and a unique nonce per message.
4. **Manage the lifecycle** — storage in a TPM/HSM/key vault, rotation, revocation, destruction (NIST SP 800-57).

Standards to know: AES (FIPS 197), ISO/IEC 18033-2 (asymmetric ciphers) and 18033-3 (block ciphers), ISO/IEC 29192
(lightweight crypto for constrained devices), NIST SP 800-175B (which standard to use when), and **FIPS 140-2/140-3**,
which validates crypto *modules* — government buyers require a validated module, not just a good algorithm.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact · [T1573](https://attack.mitre.org/techniques/T1573/) Encrypted Channel · [T1600](https://attack.mitre.org/techniques/T1600/) Weaken Encryption |
| **What it leads to** | done right: stolen laptops and sniffed traffic are useless to an attacker; done wrong: false sense of security |
| **Where defenders meet it** | audit findings (weak ciphers, unencrypted disks), ransomware (attackers use the same AES/RSA), C2 hidden in TLS |

## Do it

Encryption-at-rest status on hosts you manage:

```powershell
# BitLocker state and encryption method per volume (XtsAes256 is the strong default)
Get-BitLockerVolume | Select-Object -Property MountPoint, VolumeStatus, EncryptionMethod, ProtectionStatus
# Is the OS forced into FIPS-validated algorithms? (1 = on)
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -ErrorAction SilentlyContinue
```

```bash
# LUKS-encrypted block devices (FSTYPE crypto_LUKS)
lsblk -f
# Ciphers this OpenSSL build offers for AEAD
openssl list -cipher-algorithms | grep -iE "gcm|chacha"
# Encrypt a file for a recipient with GPG (hybrid: RSA/ECC wraps an AES key)
gpg --encrypt --recipient alice@example.com report.pdf
```

## See it

| Source | What you see |
| :--- | :--- |
| `Get-BitLockerVolume` / `manage-bde -status` | `FullyEncrypted` + `ProtectionStatus On`; `Off` means the key is stored in clear |
| TLS scan of your own service | protocol and cipher suite agreed — TLS 1.2+ with ECDHE + AES-GCM is the target |
| Code review | `ECB`, `DES`, `MD5`, hard-coded keys or IVs, `Random()` instead of a CSPRNG |

## Detect it

- Administer: [BitLocker recovery](../../tasks/administration/bitlocker-recovery.md)
- Harden: [TLS & SSL](../networking/tls-ssl.md) · [PKI](../identity/pki.md) · [SSH keys](../identity/ssh-keys.md)
- Detect weak crypto in use: [Cryptographic attacks](cryptographic-attacks.md) — RC4 Kerberos tickets, legacy TLS
- Prepare for quantum: [Post-quantum cryptography](post-quantum-cryptography.md)

## Related concepts

- [Encrypt Linux disks with LUKS2](../../tasks/administration/linux-luks-disk-encryption.md) · [BitLocker recovery](../../tasks/administration/bitlocker-recovery.md)
- [Hash Functions](hash-functions.md) · [Digital Signatures](digital-signatures.md) · [Cryptographic Attacks](cryptographic-attacks.md) · [Post-Quantum Cryptography](post-quantum-cryptography.md)
