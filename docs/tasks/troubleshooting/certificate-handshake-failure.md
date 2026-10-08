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

<div class="cc-tree" data-title="Interactive TLS/SSL Handshake Diagnostic Tree" markdown>

<div class="cc-node cc-node--root" data-id="step-l4-reachability" markdown>

#### Step 1: Layer 4 TCP Port Reachability Check

Before analyzing cryptographic negotiations, verify whether the transport socket to port 443 can even establish:

```bash
# Linux: Test TCP socket connection (timeout 5s)
nc -zv -w 5 <TARGET_HOST> 443
# Or via native bash /dev/tcp
(timeout 3 bash -c "</dev/tcp/<TARGET_HOST>/443") && echo "Port 443 open" || echo "Port 443 unreachable"
```
```powershell
# Windows: Test TCP port 443 reachability
Test-NetConnection -ComputerName "<TARGET_HOST>" -Port 443
```

**Did the TCP socket connection establish successfully?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-tls-probe">✓ Port 443 Connected (Error occurs during TLS negotiation)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-l4-blocked">✗ Connection Timed Out / Refused (No TCP handshake)</button>
</div>

</div>

<div class="cc-node" data-id="step-l4-blocked" markdown>

#### Diagnostic Branch: Layer 4 Network / Firewall Blockage

The failure occurs **before** TLS negotiation begins. The TCP SYN was either silently dropped by an egress/ingress firewall or rejected with RST:

```powershell
# Windows: Check local firewall rules and routing
Get-NetRoute -DestinationPrefix "0.0.0.0/0"
Get-NetFirewallRule -Direction Outbound -Enabled True | Where-Object { $_.DisplayName -match "HTTPS|443" }
```
```bash
# Linux: Trace TCP path and inspect iptables/nftables
traceroute -T -p 443 <TARGET_HOST>
sudo iptables -L OUTPUT -n -v | grep 443
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-tls-probe" markdown>

#### Step 2: TLS Handshake & Certificate Chain Negotiation

Connect using OpenSSL or PowerShell with verbose certificate chain dumping to capture the exact handshake rejection alert:

```bash
# Linux: Perform TLS handshake and inspect certificate chain
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -showcerts 2>&1 | head -n 30
```
```powershell
# Windows: Probe SSL stream and retrieve remote certificate properties
$TcpClient = New-Object System.Net.Sockets.TcpClient("<TARGET_HOST>", 443)
$SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $false, { $true })
$SslStream.AuthenticateAsClient("<TARGET_HOST>")
$Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$SslStream.RemoteCertificate
[PSCustomObject]@{
    Subject     = $Cert.Subject
    Issuer      = $Cert.Issuer
    ValidFrom   = $Cert.NotBefore
    ValidTo     = $Cert.NotAfter
    CipherSuite = $SslStream.NegotiatedCipherSuite
    Protocol    = $SslStream.SslProtocol
}
$SslStream.Close(); $TcpClient.Close()
```

**What error does the TLS handshake return?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-chain-missing">Missing Intermediate CA / Incomplete Chain (unable to get local issuer certificate)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-san-mismatch">Hostname / SAN Mismatch (CN does not match requested host)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-cipher-protocol">Protocol / Cipher Incompatibility (handshake_failure / SEC_E_INVALID_TOKEN)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-cert-expired">Expired Certificate or Clock Skew (certificate has expired)</button>
</div>

</div>

<div class="cc-node" data-id="step-chain-missing" markdown>

#### Diagnostic Branch: Incomplete Certificate Chain (Missing Intermediate CA)

**Symptom**: Web browsers connect without error (due to AIA fetching or local intermediate caching), but command-line tools (`curl`, `Invoke-RestMethod`, API clients) fail with `SSL_ERROR_SYSCALL` or `unable to get local issuer certificate`.
**Root Cause**: The web server only serves the leaf certificate instead of the complete bundle (leaf + intermediate CA).

```bash
# 1. Inspect the certificate chain depth returned by the server (depth should be >= 2)
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> 2>&1 | grep -E "depth|verify error|verify return"

# 2. Extract Authority Information Access (AIA) issuer URL to locate missing intermediate
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> 2>/dev/null | \
  openssl x509 -noout -text | grep -A 4 "Authority Information Access"

# 3. Remediation: Reconfigure web server (Nginx/Apache/Envoy) to bundle fullchain.pem
# Nginx: ssl_certificate /etc/letsencrypt/live/<TARGET_HOST>/fullchain.pem;
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-san-mismatch" markdown>

#### Diagnostic Branch: Hostname / Subject Alternative Name (SAN) Mismatch

**Symptom**: Error `certificate verify failed: IP address mismatch` or `hostname does not match certificate subject`.
**Root Cause**: Modern TLS clients require the accessed domain or IP to match an entry in the **Subject Alternative Name (SAN)** extension (RFC 6125 deprecates CN fallback).

```bash
# Inspect all Subject Alternative Names (SANs) on the remote certificate
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName
```
```powershell
# Windows: Parse SAN extension entries
$Cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } | ForEach-Object { $_.Format($true) }
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-cipher-protocol" markdown>

#### Diagnostic Branch: Protocol Version or Cipher Suite Mismatch

**Symptom**: OpenSSL error `handshake_failure`, `no protocols available`, or Windows `SEC_E_INVALID_TOKEN`.
**Root Cause**: Server enforces TLS 1.2 / 1.3 with strict AEAD ciphers while client attempts TLS 1.0/1.1 or deprecated CBC/RSA ciphers.

```bash
# Test explicit TLS versions to pinpoint supported protocol floor
openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -tls1_2 < /dev/null
openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -tls1_3 < /dev/null
```
```powershell
# Windows: Enforce TLS 1.2 on legacy PowerShell 5.1 sessions before calling API
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-cert-expired" markdown>

#### Diagnostic Branch: Expired Certificate or System Clock Skew

**Symptom**: `certificate has expired` or `not yet valid`.
**Root Cause**: Either the server's certificate validity period has lapsed, or the client host's system clock has drifted significantly out of sync.

```bash
# 1. Check exact certificate expiration timestamps
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> 2>/dev/null | openssl x509 -noout -dates

# 2. Check local client clock synchronization against NTP
timedatectl status
```
```powershell
# Windows: Check local system time against domain controller / NTP
w32tm /query /status
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

</div>

## 2. Live Diagnostics & Inspection Reference

### Linux / OpenSSL Deep-Dive
```bash
# 1. Test full handshake and print certificate chain details
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -showcerts

# 2. Check validity dates and SAN entries explicitly
echo | openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> 2>/dev/null |
  openssl x509 -noout -dates -subject -issuer -ext subjectAltName

# 3. Test explicit TLS version negotiation
openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -tls1_2
openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -tls1_3
```

### Windows (PowerShell)
```powershell
# 1. Query remote SSL certificate and validate chain
$TcpClient = New-Object System.Net.Sockets.TcpClient("<TARGET_HOST>", 443)
$SslStream = New-Object System.Net.Security.SslStream($TcpClient.GetStream(), $false, { $true })
$SslStream.AuthenticateAsClient("<TARGET_HOST>")
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

- **Missing Intermediate Certificate**: If browsers succeed but curl/PowerShell fail, the server is omitting the intermediate certificate. Bundle the intermediate CA into the server's certificate file (`fullchain.pem`).
- **TLS 1.0/1.1 Deprecation**: Modern Linux kernels and Windows Server 2022 disable legacy protocols by default. Upgrade client libraries or update target services to TLS 1.2+.
- **SNI Requirement**: Modern reverse proxies host multiple certificates behind one IP. Always supply `-servername <TARGET_HOST>` in OpenSSL or modern Host header requests.
