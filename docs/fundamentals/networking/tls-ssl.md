---
title: Fundamentals — TLS Handshake & Cipher Suite Mechanics
type: entry
platforms:
  - Linux
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Hardening
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - tls
  - ssl
  - cryptography
  - ciphers
---

# Fundamentals — TLS Handshake & Cipher Suite Mechanics

Transport Layer Security (TLS) provides confidentiality, data integrity, and endpoint authentication across modern IP transport channels.

## 1. TLS 1.3 Handshake (1-RTT)

```text
[Client] ──(1) ClientHello + Supported Ciphers + Key Share (ECDHE)──► [Server]
[Client] ◄──(2) ServerHello + Server Key Share + EncryptedExtensions ─ [Server]
[Client] ◄──(3) Certificate + CertificateVerify + Finished─────────── [Server]
[Client] ──(4) Finished (Symmetric Keys Established)────────────────► [Server]
```

*TLS 1.3 eliminates obsolete renegotiation, supports 0-RTT resumption, and mandates forward secrecy (PFS).*

---

## 2. Cipher Suite Structure

Example: `TLS_AES_256_GCM_SHA384` (TLS 1.3) or `ECDHE-RSA-AES256-GCM-SHA384` (TLS 1.2)
- **Key Exchange**: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) for Perfect Forward Secrecy.
- **Authentication**: RSA or ECDSA digital certificates.
- **Bulk Encryption**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Integrity (MAC)**: SHA-384.

---

## 3. Auditing Server TLS Configuration

```bash
# Test supported TLS versions and certificate validity with OpenSSL
openssl s_client -connect example.com:443 -tls1_3
openssl s_client -connect example.com:443 -showcerts
```
