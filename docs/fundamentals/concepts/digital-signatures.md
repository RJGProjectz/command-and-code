---
title: Digital Signatures and Non-repudiation (RSA, DSA, ECDSA, EdDSA, PGP)
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, Bash]
tasks: [Investigation, Hardening, Forensics]
category: Cryptography
security_domain: Data Protection
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, cryptography, signatures, code-signing, pgp]
aliases: [Digital Signature Algorithm, Elliptic Curve Digital Signature Algorithm, Non-repudiation, Pretty Good Privacy (PGP), ISOIEC 14888-3, Digital Identity and Trust]
difficulty: intermediate
verified: false
---

# Digital Signatures and Non-repudiation (RSA, DSA, ECDSA, EdDSA, PGP)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** a digital signature is a hash of the data processed with a private key, so anyone with the public key can check who signed it and that nothing changed since.

## What it is

Signatures give **integrity**, **authenticity** and **non-repudiation**: the signer cannot plausibly deny signing,
because only they hold the private key. They secure code (Authenticode, package managers), documents, email (S/MIME,
PGP), certificates ([PKI](../identity/pki.md)), Kerberos and SAML tokens, and blockchain transactions.

| Algorithm | Based on | Notes |
| :--- | :--- | :--- |
| RSA (PKCS#1 v1.5, PSS) | factoring | most common for code-signing and certificates |
| DSA | discrete log | legacy; FIPS 186-5 (2023) no longer approves it for new signatures |
| ECDSA (P-256, secp256k1) | elliptic curves | small keys; a **reused or biased nonce leaks the private key** (PlayStation 3, 2010) |
| EdDSA (Ed25519) | Edwards curves | deterministic nonces, fast, preferred for SSH keys |
| ML-DSA, SLH-DSA | lattices / hashes | quantum-resistant — see [post-quantum cryptography](post-quantum-cryptography.md) |

ISO/IEC 14888-3 standardises discrete-logarithm signatures (DSA, ECDSA family). **PGP/GPG** uses a web of trust instead
of certificate authorities: users sign each other's keys.

## How it works

1. **Sign:** hash the data → apply the private key to the hash → attach the signature (and usually the certificate).
2. **Verify:** hash the received data → check the signature with the public key → check that the certificate chains to
   a trusted root and is not revoked or expired.
3. **Timestamp:** a trusted timestamp proves the signature existed while the certificate was valid, so signed code
   keeps working after the certificate expires.

Signatures prove **who signed**, not that the content is safe: attackers steal or buy code-signing certificates.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1553.002](https://attack.mitre.org/techniques/T1553/002/) Code Signing · [T1588.003](https://attack.mitre.org/techniques/T1588/003/) Obtain Code Signing Certificates · [T1606.002](https://attack.mitre.org/techniques/T1606/002/) Forge SAML Tokens |
| **What it leads to** | trusted-looking malware, forged tokens (Golden SAML), supply-chain compromise via a stolen signing key |
| **Where defenders meet it** | unsigned binaries in odd paths, valid signatures from unexpected publishers, revoked certificates |

## Do it

```powershell
# Signature status, signer and timestamp of a binary
Get-AuthenticodeSignature -FilePath C:\Windows\System32\notepad.exe |
    Select-Object -Property Status, SignerCertificate, TimeStamperCertificate
# Unsigned or badly signed executables in user-writable places
Get-ChildItem -Path $env:APPDATA, $env:TEMP -Include *.exe, *.dll -Recurse -ErrorAction SilentlyContinue |
    Get-AuthenticodeSignature | Where-Object -Property Status -NE -Value 'Valid'
```

```bash
# Verify a detached GPG signature on a download
gpg --verify release.tar.gz.asc release.tar.gz
# Verify an RSA/ECDSA signature with OpenSSL
openssl dgst -sha256 -verify pubkey.pem -signature file.sig file.bin
```

## See it

| Source | What you see |
| :--- | :--- |
| Sysmon event 7 (image load) | `Signed`, `Signature`, `SignatureStatus` for every DLL |
| Defender `DeviceFileCertificateInfo` | signer, issuer, `IsTrusted`, `CertificateSerialNumber` — pivot on a stolen certificate |
| WDAC / AppLocker logs | blocks for unsigned or untrusted-publisher code |

## Detect it

- Harden: [AppLocker deployment](../../tasks/hardening/applocker-deployment-rollout.md) — publisher rules
- Investigate: [Suspicious service](../../tasks/investigation/suspicious-service.md) — check the signer of the service binary
- Background: [PKI](../identity/pki.md) · [UEFI Secure Boot](../systems/uefi-secure-boot.md)

## Related concepts

- [Hash Functions](hash-functions.md) · [Cryptography Fundamentals](cryptography-fundamentals.md) · [Post-Quantum Cryptography](post-quantum-cryptography.md)
