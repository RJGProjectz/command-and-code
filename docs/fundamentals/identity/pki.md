---
title: Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation
type: entry
platforms:
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - pki
  - certificates
  - x509
  - ocsp
---

# Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation

Public Key Infrastructure (PKI) manages digital certificates, public keys, and cryptographic trust chains across enterprise environments.

## 1. Trust Hierarchy

```text
[Root Certificate Authority (Offline / Air-Gapped)]
                       │
          [Intermediate / Issuing CA]
          ┌────────────┴────────────┐
   [Server SSL Cert]         [User Smartcard / VPN Cert]
```

## 2. Certificate Revocation Mechanics

- **CRL (Certificate Revocation List)**: Periodically published signed file containing revoked serial numbers. High latency (updates every 24–48 hours).
- **OCSP (Online Certificate Status Protocol)**: Real-time query to an OCSP responder (`Good`, `Revoked`, `Unknown`) with OCSP Stapling to minimize handshake latency.
