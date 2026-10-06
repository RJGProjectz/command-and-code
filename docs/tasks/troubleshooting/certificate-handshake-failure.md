---
title: Troubleshooting — TLS/SSL Handshake & Certificate Failures
type: workflow
platforms:
  - Linux
  - Windows
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Troubleshooting
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - tls
  - ssl
  - certificate
  - handshake
  - openssl
---

# Troubleshooting — TLS/SSL Handshake & Certificate Failures

Systematic diagnostic tree for resolving HTTPS negotiation errors, missing intermediate certificate chains, protocol version mismatches, and hostname SAN verification failures.

## 1. Handshake Diagnostic Flow

```text
[TLS Connection Failure: SEC_E_INVALID_TOKEN / SSL_ERROR_SYSCALL / CERT_UNTRUSTED]
       │
       ▼
1. Is TCP Port 443 Reachable?
       ├─ No  ──► Check Layer 4 Firewall / NAT / Security Group rules
       └─ Yes ──► Continue
       │
       ▼
2. Connect with OpenSSL / Test-NetConnection
       ├─ Protocol Mismatch  ──► Client or server lacks common TLS version (TLS 1.2 vs 1.3)
       ├─ Cipher Mismatch    ──► Incompatible cipher suite offerings
       ├─ Chain Error        ──► Server omitted intermediate CA certificate
       └─ Hostname Mismatch  ──► Subject Alternative Name (SAN) missing requested FQDN
```

## 2. Live Diagnostics & Inspection

### Linux / OpenSSL Deep-Dive
```bash
# 1. Test full handshake and print certificate chain details
echo | openssl s_client -connect app.example.com:443 -servername app.example.com -showcerts

# 2. Check validity dates and SAN entries explicitly
echo | openssl s_client -connect app.example.com:443 -servername app.example.com 2>/dev/null |
  openssl x509 -noout -dates -subject -issuer -ext subjectAltName

# 3. Test explicit TLS version negotiation
openssl s_client -connect app.example.com:443 -tls1_2
openssl s_client -connect app.example.com:443 -tls1_3
```

### Windows (PowerShell)
```powershell
# 1. Query remote SSL certificate and validate chain
$TcpClient = New-Object System.Net.Sockets.TcpClient("app.example.com", 443)
$SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $false, { $true })
$SslStream.AuthenticateAsClient("app.example.com")
$Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate

[PSCustomObject]@{
    Subject     = $Cert.Subject
    Issuer      = $Cert.Issuer
    ValidFrom   = $Cert.NotBefore
    ValidTo     = $Cert.NotAfter
    CipherSuite = $SslStream.NegotiatedCipherSuite
    Protocol    = $SslStream.SslProtocol
}
$SslStream.Close()
$TcpClient.Close()
```

## 3. Root Cause Remediations

- **Missing Intermediate Certificate**: If browsers succeed but curl/PowerShell fail, the server is omitting the intermediate certificate. Bundle the intermediate CA into the server's certificate file (fullchain.pem).
- **TLS 1.0/1.1 Deprecation**: Modern Linux kernels and Windows Server 2022 disable legacy protocols by default. Upgrade client libraries or update target services to TLS 1.2+.
