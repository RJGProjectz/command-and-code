---
title: Administration — TLS/SSL Certificate Deployment & Web Server Hardening
type: workflow
platforms:
  - Linux
  - Windows
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - tls
  - ssl
  - certificate
  - openssl
  - nginx
  - apache
  - iis
  - certbot
  - hardening
---

# Administration — TLS/SSL Certificate Deployment & Web Server Hardening

Production runbook for generating Certificate Signing Requests (CSRs) with Subject Alternative Names, correctly assembling intermediate certificate chains, deploying hardened web server configurations (Nginx, Apache, IIS), and automating ACME lifecycle renewals.

---

## 1. CSR & Private Key Generation (OpenSSL)

Modern browsers and cryptographic libraries reject certificates that lack the **Subject Alternative Name (SAN)** extension (RFC 6125). Never generate CSRs with only a legacy Common Name (CN).

### Generate SAN Configuration File (`san.cnf`)
```bash
cat << 'EOF' > san.cnf
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[dn]
C  = US
ST = California
L  = San Francisco
O  = Example Corp
OU = Infrastructure
CN = <PRIMARY_DOMAIN>

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = <PRIMARY_DOMAIN>
DNS.2 = *.<PRIMARY_DOMAIN>
DNS.3 = api.<PRIMARY_DOMAIN>
EOF
```

### Generate Key & CSR (Ed25519 or RSA 4096)
```bash
# Option A: Modern Ed25519 (Fastest, compact, highly secure)
openssl req -new -newkey ed25519 -nodes \
  -keyout '<PRIMARY_DOMAIN>.key' \
  -out '<PRIMARY_DOMAIN>.csr' \
  -config san.cnf

# Option B: High-compatibility RSA 4096-bit
openssl req -new -newkey rsa:4096 -nodes \
  -keyout '<PRIMARY_DOMAIN>.key' \
  -out '<PRIMARY_DOMAIN>.csr' \
  -config san.cnf

# Restrict private key permissions immediately
chmod 600 '<PRIMARY_DOMAIN>.key'
```

### Verify CSR Extensions & SANs
```bash
openssl req -in '<PRIMARY_DOMAIN>.csr' -noout -text | grep -A 4 "Subject Alternative Name"
```

---

## 2. Assembling the Certificate Bundle (`fullchain.pem`)

When a Certificate Authority (CA) signs your CSR, they return your leaf certificate (`cert.crt`) and one or more intermediate certificates (`intermediate.crt`).

### The Chain Assembly Golden Rule
Web servers require certificates in exact top-down hierarchical order. **Never include the Root CA** in the server certificate bundle (root CAs are already pre-installed in the client's OS trust store; serving them wastes packet bytes and can trigger validation rejections).

```bash
# Order: [Leaf Certificate] + [Intermediate CA 1] + [Intermediate CA 2 (if present)]
cat '<PRIMARY_DOMAIN>.crt' intermediate.crt > fullchain.pem

# Verify certificate bundle order and depth (depth must be >= 2)
openssl crl2pkcs7 -nocrl -certfile fullchain.pem | openssl pkcs7 -print_certs -noout | grep -E "subject=|issuer="
```

---

## 3. Web Server Deployment & Transport Hardening

### Nginx Hardened Configuration (`/etc/nginx/conf.d/tls.conf`)
Enforce TLS 1.2 and 1.3 only, modern AEAD cipher suites, HSTS, and OCSP Stapling:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name <PRIMARY_DOMAIN>;

    # Certificate bundle and private key
    ssl_certificate /etc/ssl/certs/fullchain.pem;
    ssl_certificate_key /etc/ssl/private/<PRIMARY_DOMAIN>.key;

    # Protocol floor & ciphers (Disables obsolete TLS 1.0 & 1.1)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    # Session caching for performance
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # OCSP Stapling (Improves TLS negotiation speed & client privacy)
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/ssl/certs/fullchain.pem;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    # HTTP Strict Transport Security (HSTS) - 1 Year with preloading
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    root /var/www/html;
}
```

```bash
# Validate Nginx syntax and reload safely
sudo nginx -t && sudo systemctl reload nginx
```

### Windows Server IIS (PowerShell)
Convert PEM files into PKCS#12 (`.pfx`) format and bind to IIS:

```powershell
# 1. Package certificate and private key into password-protected PFX
openssl pkcs12 -export -out "certificate.pfx" -inkey "<PRIMARY_DOMAIN>.key" -in "fullchain.pem" -password "pass:<EXPORT_PASSWORD>"

# 2. Import PFX into Windows LocalMachine\My Store
$CertPassword = ConvertTo-SecureString "<EXPORT_PASSWORD>" -AsPlainText -Force
$Cert = Import-PfxCertificate -FilePath "certificate.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $CertPassword

# 3. Bind Certificate to IIS HTTPS Binding on port 443
Import-Module WebAdministration
$Binding = Get-WebBinding -Name "Default Web Site" -Protocol https
if (-not $Binding) {
    New-WebBinding -Name "Default Web Site" -IPAddress "*" -Port 443 -Protocol https
}
Get-WebBinding -Name "Default Web Site" -Protocol https | ForEach-Object {
    $_.AddSslCertificate($Cert.GetCertHashString(), "My")
}
```

---

## 4. Automated Certificate Lifecycle (Certbot / ACME)

Automate zero-touch 90-day certificate rotations using Let's Encrypt:

```bash
# Issue certificate via ACME HTTP-01 challenge with Nginx reload hook
sudo certbot certonly --webroot -w /var/www/html \
  -d '<PRIMARY_DOMAIN>' -d 'api.<PRIMARY_DOMAIN>' \
  --email 'admin@<PRIMARY_DOMAIN>' --agree-tos --no-eff-email \
  --deploy-hook "systemctl reload nginx"

# Test automated renewal without making changes
sudo certbot renew --dry-run
```

---

## 5. Post-Deployment Verification Checklist

```bash
# 1. Verify exact negotiated TLS protocol and cipher
echo | openssl s_client -connect '<PRIMARY_DOMAIN>:443' -servername '<PRIMARY_DOMAIN>' 2>&1 | grep -E "Protocol|Cipher"

# 2. Confirm OCSP Stapling response is active
echo | openssl s_client -connect '<PRIMARY_DOMAIN>:443' -servername '<PRIMARY_DOMAIN>' -status 2>&1 | grep -A 5 "OCSP Response Data"

# 3. Verify TLS 1.0 and 1.1 are actively refused
openssl s_client -connect '<PRIMARY_DOMAIN>:443' -tls1 2>&1 | grep "handshake failure"
openssl s_client -connect '<PRIMARY_DOMAIN>:443' -tls1_1 2>&1 | grep "handshake failure"
```

---

## Related Guides

- [Troubleshooting — TLS/SSL Handshake & Certificate Failures](../troubleshooting/certificate-handshake-failure.md)
- [Fundamentals — TLS Handshake & Cipher Suite Mechanics](../../fundamentals/networking/tls-ssl.md)
- [Fundamentals — PKI Architecture, X.509 & Chain Validation](../../fundamentals/identity/pki.md)
- [Administration — Certificate and PKI Management](certificate-and-pki-management.md)
