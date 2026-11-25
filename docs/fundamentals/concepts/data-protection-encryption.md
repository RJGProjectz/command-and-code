---
title: Data Protection and Encryption
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, Python, Bash]
tasks: [Hardening, Governance, Assurance]
category: Cryptography and Data Security
security_domain: Application
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, encryption, data-protection, TLS, AES, key-management, at-rest, in-transit]
aliases: [data encryption, encryption at rest, encryption in transit, TDE, database encryption, key management]
difficulty: intermediate
verified: false
---

# Data Protection and Encryption
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** data protection is the practice of shielding sensitive information from unauthorized access through encryption at rest, encryption in transit, and strict key management.

## What it is

Encryption is the cornerstone of data protection: it transforms readable plaintext into ciphertext that can only be reversed with the correct key. Modern security programs distinguish two threat surfaces — data at rest (stored on disk, in a database, or on removable media) and data in transit (moving across a network between a client and a server, or between services). Both surfaces require distinct controls, and protecting them is a regulatory requirement under frameworks such as GDPR, HIPAA, PCI DSS, and ISO/IEC 27001 [Defensive Security Handbook, 2nd ed., p.168].

Encryption alone is insufficient without proper key management. A well-encrypted database is only as secure as the key used to unlock it. Key lifecycle practices — generation, distribution, rotation, and revocation — are as important as the cryptographic algorithm itself [Pentesting APIs, p.254].

## How it works

### Data at rest

Sensitive data stored on disk should be encrypted using a symmetric algorithm. The modern standard is **AES-256** (Advanced Encryption Standard with 256-bit key length), which provides computational security beyond the foreseeable lifetime of classical hardware. Avoid legacy algorithms such as DES (56-bit key, broken) or 3DES (deprecated by NIST in 2017). For databases specifically, **Transparent Data Encryption (TDE)** encrypts data at the page level before it is written to disk and decrypts it transparently when read into memory — the application is unaware of encryption, which eliminates the risk of developer errors [Defensive Security Handbook, 2nd ed., p.169].

For application-level encryption (encrypting specific fields before database storage), use a well-tested library rather than rolling your own crypto:

```python
# Python — symmetric field encryption with Fernet (AES-128-CBC + HMAC)
from cryptography.fernet import Fernet

key = Fernet.generate_key()       # 32-byte random key — store in a KMS, NOT in source
cipher = Fernet(key)
encrypted_ssn = cipher.encrypt(b"123-45-6789")
# Store encrypted_ssn in the database, never the plaintext
```

> [!CAUTION]
> Never hardcode encryption keys in source code, configuration files, or environment variables checked into version control. Keys belong in a managed secrets store such as Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault.

### Data in transit

Encryption in transit prevents network eavesdropping and man-in-the-middle attacks. The standard mechanism is **TLS 1.2 or 1.3**. Older protocols (TLS 1.0, TLS 1.1, SSLv3) contain known vulnerabilities and must be disabled. All service-to-service communication — API calls, database connections, internal microservices, replication traffic — should traverse an encrypted channel.

```powershell
# PowerShell — verify TLS protocol used by a remote endpoint
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$req = [Net.WebRequest]::Create("https://example.com")
$resp = $req.GetResponse()
Write-Host "Protocol: $($resp.ResponseUri.Scheme)"
```

For Java and JVM-based services, prefer **AES/GCM/NoPadding** over CBC mode — GCM provides authenticated encryption, detecting tampering in addition to providing confidentiality [Pentesting APIs, p.254].

### Key management

An encryption system is only as strong as its key management. Best practices:

| Practice | Rationale |
| :--- | :--- |
| **Hardware Security Modules (HSMs) or cloud KMS** | Keys never leave the secure boundary; software-only key stores are vulnerable to memory scraping |
| **Key rotation** | Rotating keys limits the blast radius of a compromised key to the data encrypted with it |
| **Separation of duties** | The entity that encrypts data should not have exclusive control of the keys |
| **Audit logging** | Every key access and rotation event should be logged for forensic accountability |
| **Avoid key persistence on the same host as data** | A breach that exposes both the ciphertext and the key on the same disk nullifies encryption |

A practical key management lifecycle from [Defensive Security Handbook, 2nd ed., p.170]:

1. **Assess** — classify data by sensitivity; prioritize encryption for PII, financial, and secrets.
2. **Choose algorithm and mode** — AES-256 at rest; TLS 1.3 in transit; AES-GCM for authenticated encryption.
3. **Generate and store keys** — use a managed KMS (HashiCorp Vault, Azure Key Vault, AWS KMS).
4. **Implement TDE** for database workloads where field-level encryption is impractical.
5. **Rotate keys** on a defined schedule (at least annually; immediately on suspected compromise).
6. **Audit and test** — verify encryption is active, certificates are not expired, and fallback to plaintext does not occur.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1552](https://attack.mitre.org/techniques/T1552/) — Unsecured Credentials; [T1040](https://attack.mitre.org/techniques/T1040/) — Network Sniffing |
| **What it prevents** | Attackers who exfiltrate a database or intercept network traffic gain only unreadable ciphertext |
| **Regulatory drivers** | GDPR Art. 32 (technical measures), HIPAA §164.312(a)(2)(iv) (encryption), PCI DSS Req. 3.5 |
| **Where defenders meet it** | Data breach investigations, cloud storage misconfiguration alerts, TLS downgrade detections |

Encryption does not replace access control — a user with legitimate database access reads plaintext regardless of TDE. It is a last line of defence against physical theft, storage-layer compromise, and passive interception [Defensive Security Handbook, 2nd ed., p.167].

## Do it

Inspect the encryption state of a Windows database server:

```powershell
# Check TDE status on SQL Server (requires VIEW SERVER STATE)
Invoke-Sqlcmd -Query @"
SELECT name, is_encrypted, encryption_state,
       encryption_state_desc
FROM sys.databases
WHERE name NOT IN ('master','tempdb','model','msdb')
"@ -TrustServerCertificate
```

Check TLS certificate expiry for a remote endpoint:

```powershell
# View TLS certificate details for a host
$tcp = [Net.Sockets.TcpClient]::new("example.com", 443)
$ssl = [Net.Security.SslStream]::new($tcp.GetStream())
$ssl.AuthenticateAsClient("example.com")
$cert = $ssl.RemoteCertificate
Write-Host "Subject: $($cert.Subject)"
Write-Host "Expires: $($cert.GetExpirationDateString())"
$tcp.Close()
```

Check which TLS versions a server accepts:

```bash
# Enumerate TLS versions with OpenSSL
for ver in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo -n "$ver: "
  openssl s_client -$ver -connect example.com:443 </dev/null 2>&1 | grep -E "New|no peer" | head -1
done
```

## See it

Evidence that encryption is absent or misconfigured:

| Source | What you see |
| :--- | :--- |
| SQL Server `sys.databases` | `is_encrypted = 0` for databases holding PII |
| Wireshark / packet capture | Cleartext HTTP, MySQL protocol, or LDAP without TLS on the wire |
| AWS S3 / Azure Blob | Buckets with `sse_algorithm: none` or public read ACLs on data stores |
| Certificate transparency logs | Expired or soon-to-expire certificates for public endpoints |
| Windows Event log | Schannel Event 36888 (TLS alert) indicating client/server negotiation failures |

## Detect it

- Detection: build a [Splunk SPL query](../../detection/spl/index.md) to alert on HTTP traffic on port 80 to internal services that should use HTTPS
- Cross-reference: [Cryptography Fundamentals](cryptography-fundamentals.md), [Cryptographic Attacks](cryptographic-attacks.md), [Privacy Laws and Data Protection](privacy-laws.md)

---
*Sources: Pentesting APIs (Packt, 2023), p. 252–254; Defensive Security Handbook, 2nd ed. (O'Reilly, 2023), p. 167–170.*
