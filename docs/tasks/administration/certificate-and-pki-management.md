---
title: Certificate and PKI Management
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, Bash]
tasks: [Administration, Hardening]
category: Application
tags: [certificates, ssl, tls, pki, pfx, certbot, let's encrypt, iis, nginx, expiration]
aliases: [check certificate expiration, renew ssl, import pfx, certutil, openssl commands, iis certificate binding]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# Certificate and PKI Management

> **Created**: 2026-10-06T18:45:00Z  
> **Last Modified**: 2026-10-06T18:45:00Z  
> **Author**: RJGProjectz  

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Expired certificates cause sudden service outages; misconfigured cipher suites introduce vulnerabilities.
> 1. Set automated alerts for certificates expiring within 30 days.
> 2. Protect exported private keys with strong passwords and restrict file system permissions (`0600` on Linux, ACL on Windows).
> 3. Verify TLS bindings and web server reloads after renewing certificates.

**Trigger:** Certificate expiration alert, web server migration, internal PKI issuance, or new service HTTPS enablement.

**Goal:** Audit certificate health, generate requests, install renewed certificates, and verify active cipher bindings across Windows and Linux.

---

## 1. Audit Expiring Certificates (Proactive Discovery)

### Windows Certificate Store (`Cert:\`)

Scan local machine personal certificates expiring within 45 days:

```powershell
$ThresholdDays = 45
Get-ChildItem -Path Cert:\LocalMachine\My |
    Where-Object { $_.NotAfter -lt (Get-Date).AddDays($ThresholdDays) } |
    Select-Object Subject, Thumbprint, NotAfter, @{N='DaysRemaining';E={($_.NotAfter - (Get-Date)).Days}} |
    Sort-Object NotAfter
```

### Linux File System & Remote Endpoint (`openssl`)

Inspect an on-disk PEM certificate:

```bash
openssl x509 -in /etc/ssl/certs/app.crt -noout -subject -dates -issuer
```

Test a live web server over the network for expiration and certificate chain:

```bash
echo | openssl s_client -servername '<APP_HOST>.<DOMAIN>' -connect '<APP_HOST>.<DOMAIN>:443' 2>/dev/null |
    openssl x509 -noout -dates -subject
```

---

## 2. Windows Server: Import PFX & Bind to IIS

### Step 1: Import PFX into Computer Personal Store

```powershell
$PfxPath = 'C:\Staging\<CERT_NAME>.pfx'
$Password = Read-Host -Prompt 'Enter PFX Private Key Password' -AsSecureString

# Import with non-exportable private key (Hardening best practice)
Import-PfxCertificate -FilePath $PfxPath `
                      -CertStoreLocation Cert:\LocalMachine\My `
                      -Password $Password
```

### Step 2: Bind Certificate to IIS HTTPS Website

```powershell
Import-Module WebAdministration

$Thumbprint = (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*<APP_HOST>.<DOMAIN>*' } | Select-Object -First 1).Thumbprint

# Update or create HTTPS binding on port 443
$Binding = Get-WebBinding -Name 'Default Web Site' -Protocol 'https'
if ($Binding) {
    # Update existing binding certificate hash
    $Binding.AddSslCertificate($Thumbprint, 'My')
} else {
    New-WebBinding -Name 'Default Web Site' -IPAddress '*' -Port 443 -Protocol 'https' -SslFlags 1
    Get-WebBinding -Name 'Default Web Site' -Protocol 'https' | ForEach-Object { $_.AddSslCertificate($Thumbprint, 'My') }
}
```

---

## 3. Linux: Automated Renewal via Certbot & Nginx Reload

Inspect Certbot automated renewal status:

```bash
# Check certificates managed by certbot
sudo certbot certificates

# Dry-run test automated renewal
sudo certbot renew --dry-run
```

For manual OpenSSL CSR generation:

```bash
# Generate 3072-bit private key and CSR
openssl req -new -newkey rsa:3072 -nodes \
    -keyout /etc/ssl/private/app.key \
    -out /etc/ssl/certs/app.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=<APP_HOST>.<DOMAIN>"

# Set strict permissions on private key
sudo chmod 0600 /etc/ssl/private/app.key
```

Reload Nginx without dropping existing client connections:

```bash
# Validate syntax before reload
sudo nginx -t

# Graceful configuration reload
sudo systemctl reload nginx
```

---

## Related

- [Windows Networking and DNS](../../platforms/windows/networking.md)
- [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md)
- [Linux Services with systemd](../../platforms/linux/systemd.md)
- [Cross-Platform Equivalents](../../references/equivalents.md)
