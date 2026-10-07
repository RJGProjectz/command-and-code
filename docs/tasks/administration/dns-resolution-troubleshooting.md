---
title: DNS Client Resolution and Troubleshooting
type: workflow
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - CMD
  - Bash
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - dns
  - nslookup
  - dig
  - resolve-dnsname
  - name-resolution
  - cache
---

# DNS Client Resolution and Troubleshooting

Operational procedures for diagnosing name resolution failures, inspecting specific record types (A, AAAA, MX, TXT, SRV), and purging local resolver caches.

---

## 1. Windows DNS Resolution

### PowerShell `Resolve-DnsName`

```powershell
# Standard A record resolution using system resolver
Resolve-DnsName -Name "login.microsoftonline.com"

# Query specific record types (TXT, MX, SRV)
Resolve-DnsName -Name "github.com" -Type MX
Resolve-DnsName -Name "_sip._tls.contoso.com" -Type SRV

# Query against a specific authoritative DNS nameserver
Resolve-DnsName -Name "internal.corp" -Server "10.0.0.10" -DnsOnly

# View cached DNS records stored in local resolver
Get-DnsClientCache | Select-Object Entry, Type, Status, Data

# Flush local Windows DNS resolver cache
Clear-DnsClientCache
```

### Windows CMD

```bat
:: Query record via nslookup
nslookup login.microsoftonline.com

:: Query MX records against Google Public DNS
nslookup -type=mx google.com 8.8.8.8

:: Flush and refresh DNS client resolver cache
ipconfig /flushdns
ipconfig /displaydns
```

---

## 2. Linux DNS Resolution (`dig` & `resolvectl`)

```bash
# Standard DNS A record lookup returning IP only
dig +short api.github.com

# Query specific record types with authoritative answer details
dig TXT _dmarc.google.com +multiline

# Query specific DNS nameserver directly
dig @1.1.1.1 A login.microsoftonline.com

# Inspect systemd-resolved cache statistics and active DNS servers
resolvectl status

# Flush local resolver cache in systemd-resolved
sudo resolvectl flush-caches
```
