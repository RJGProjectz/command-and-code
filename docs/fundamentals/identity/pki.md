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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - pki
  - certificates
  - x509
  - ocsp
aliases: [Digital Signature, Private Key, Public Key, Public Key Infrastructure]
---

# Fundamentals — Public Key Infrastructure (PKI), CAs & Revocation

Public Key Infrastructure (PKI) manages digital certificates, public keys, and cryptographic trust chains across enterprise environments.

A certificate binds a public key to a name (a host, user or code publisher) and is signed by a certificate authority (CA). Anyone who trusts the CA trusts the binding. That makes the CA's private key one of the most valuable secrets in the organisation: whoever holds it can impersonate any server or user.

## 1. Trust Hierarchy

```text
[Root Certificate Authority (Offline / Air-Gapped)]
                       │
          [Intermediate / Issuing CA]
          ┌────────────┴────────────┐
   [Server SSL Cert]         [User Smartcard / VPN Cert]
```

- The **root CA** signs only intermediate CAs and stays offline; if it is compromised, every certificate below it must be replaced.
- **Issuing CAs** sign end-entity certificates and can be revoked by the root without rebuilding everything.
- Clients must receive the full **chain** (server certificate + intermediates). A missing intermediate is the most common TLS error that "works in one browser but not another".

## 2. What is in a certificate

| Field | Meaning | Check |
| --- | --- | --- |
| Subject / SAN | The names the certificate is valid for | Browsers use **SAN only**; the CN is ignored |
| Issuer | Which CA signed it | Must chain to a trusted root |
| Validity | Not before / not after | Public TLS certificates are limited to 398 days, and the maximum is shrinking |
| Key Usage / Extended Key Usage | What the key may do (server auth, client auth, code signing) | A certificate with *Any Purpose* or *Client Authentication* EKU can be abused for logon |
| CRL Distribution Point / AIA | Where to check revocation and fetch the issuer | Must be reachable by clients |

## 3. Certificate Revocation Mechanics

- **CRL (Certificate Revocation List)**: Periodically published signed file containing revoked serial numbers. Clients cache it until its *Next Update* time, so revocation can take hours or days to be seen.
- **OCSP (Online Certificate Status Protocol)**: Query to an OCSP responder for one certificate (`Good`, `Revoked`, `Unknown`). **OCSP stapling** lets the server attach a recent signed OCSP response to the handshake, so clients do not need to contact the responder.

Revocation only works if clients check it: many applications "soft-fail" (accept the certificate when the CRL or OCSP server cannot be reached).

## 4. Inspect certificates

```bash
# What a server presents, including the chain
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# Decode a certificate file (-ext needs OpenSSL 3.0 or later)
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName,extendedKeyUsage
```

```powershell
# Machine certificates expiring in the next 30 days
Get-ChildItem Cert:\LocalMachine\My | Where-Object NotAfter -lt (Get-Date).AddDays(30) |
    Select-Object Subject, NotAfter, Thumbprint

# Build and verify the chain, including revocation
certutil -verify -urlfetch .\cert.cer
```

## 5. Attacks to know

| Attack | What happens | Defence |
| --- | --- | --- |
| Stolen CA key | Attacker issues trusted certificates for anything | Offline root, HSM for issuing CAs, monitor issuance |
| AD CS template abuse (ESC1–ESC8) | A low-privileged user requests a certificate that lets them log on as a domain admin | Audit templates (enrollee-supplied subject, client-auth EKU, broad enrollment rights) |
| Rogue root in the trust store | Attacker's root makes their interception certificates trusted | Monitor changes to `Cert:\LocalMachine\Root` and `/etc/ssl/certs` |
| Expired certificate | Outage, or users trained to click through warnings | Inventory and expiry alerts |

## Related

- [Certificate and PKI management](../../tasks/administration/certificate-and-pki-management.md)
- [TLS certificate deployment](../../tasks/administration/tls-certificate-deployment.md)

## Sources

- [RFC 5280 — X.509 certificate and CRL profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 6960 — OCSP](https://www.rfc-editor.org/rfc/rfc6960)
- [Microsoft Learn — Active Directory Certificate Services overview](https://learn.microsoft.com/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [SpecterOps — Certified Pre-Owned (AD CS abuse)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
