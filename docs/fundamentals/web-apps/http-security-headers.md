---
title: "Fundamentals — HTTP Security Headers & Transport Hardening"
description: "Production configuration standards for HTTP security headers: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy, and Permissions-Policy."
platforms: [Linux, Windows]
languages: [HTTP, PowerShell, Bash]
tasks: [Hardening, Assurance, Troubleshooting]
type: entry
verified: true
last_verified: 2026-10-06
difficulty: intermediate
---

# HTTP Security Headers & Transport Hardening

**HTTP Security Headers** are server response directives that instruct web browsers to enforce strict client-side security controls, activate defense-in-depth mitigations against Cross-Site Scripting (XSS), prevent Clickjacking, block MIME-type sniffing, and guarantee encrypted HTTPS transport.

Applying a complete set of hardened security headers at the edge reverse proxy (NGINX, Cloudflare, Azure Application Gateway, IIS) is a mandatory requirement for CIS Benchmark compliance and modern web application security.

---

## Enterprise HTTP Security Headers Matrix

| Header | Production Recommended Value | Purpose & Threat Mitigated |
|:---|:---|:---|
| **`Strict-Transport-Security`** (HSTS) | `max-age=63072000; includeSubDomains; preload` | Forces browsers to connect exclusively via HTTPS for 2 years. Prevents SSL Stripping and Adversary-in-the-Middle (AiTM) downgrades. |
| **`Content-Security-Policy`** (CSP) | `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';` | Whitelists approved content origins; neutralizes inline script injection and untrusted asset loading. |
| **`X-Content-Type-Options`** | `nosniff` | Prevents browsers from guessing (sniffing) MIME types. Forces execution strictly according to declared `Content-Type`. |
| **`X-Frame-Options`** | `DENY` or `SAMEORIGIN` | Forbids rendering the page inside an `<iframe>`, neutralizing **Clickjacking** attacks. |
| **`Referrer-Policy`** | `strict-origin-when-cross-origin` | Protects privacy by omitting sensitive query parameters from the `Referer` header during cross-origin navigations. |
| **`Permissions-Policy`** | `camera=(), microphone=(), geolocation=(), payment=()` | Disables browser access to device hardware APIs that the web application does not need. |
| **`Cross-Origin-Opener-Policy`** (COOP) | `same-origin` | Isolates the browsing context to defend against Spectre-style side-channel memory attacks. |
| **`Cross-Origin-Resource-Policy`** (CORP) | `same-origin` | Blocks other origins from loading internal images, scripts, or fonts. |

---

## Production Web Server Configurations

### 1. NGINX Reverse Proxy (`/etc/nginx/conf.d/security-headers.conf`)

```nginx
# Add standardized security headers to all HTTP responses
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Content Security Policy Baseline
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';" always;

# Hide server software version string
server_tokens off;
```

---

### 2. Microsoft IIS (`web.config`)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <!-- Security Headers -->
        <add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains; preload" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="X-Frame-Options" value="DENY" />
        <add name="Referrer-Policy" value="strict-origin-when-cross-origin" />
        <add name="Permissions-Policy" value="camera=(), microphone=(), geolocation=(), payment=()" />
        <add name="Content-Security-Policy" value="default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" />
        
        <!-- Remove Information Disclosure Headers -->
        <remove name="X-Powered-By" />
        <remove name="X-AspNet-Version" />
      </customHeaders>
    </httpProtocol>
    
    <!-- Disable Server Banner -->
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>
  </system.webServer>
</configuration>
```

---

## Practical Examples

### 1. PowerShell: Automated Security Header Audit & Compliance Scoring

This script audits any public or internal web endpoint, verifies header presence, and calculates a compliance score:

```powershell
function Test-HttpSecurityHeaderCompliance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Uri]$Uri
    )

    $requiredHeaders = @{
        'Strict-Transport-Security' = @{ Name = "HSTS"; Weight = 25 }
        'Content-Security-Policy'   = @{ Name = "CSP"; Weight = 25 }
        'X-Content-Type-Options'    = @{ Name = "MIME Sniffing"; Weight = 15 }
        'X-Frame-Options'           = @{ Name = "Clickjacking (XFO)"; Weight = 15 }
        'Referrer-Policy'           = @{ Name = "Referrer Policy"; Weight = 10 }
        'Permissions-Policy'        = @{ Name = "Permissions Policy"; Weight = 10 }
    }

    try {
        $response = Invoke-WebRequest -Uri $Uri -Method Head -TimeoutSec 15
        $headers = $response.Headers

        $score = 0
        $results = @()

        foreach ($headerKey in $requiredHeaders.Keys) {
            $meta = $requiredHeaders[$headerKey]
            $present = $headers.Contains($headerKey)
            $val = if ($present) { $headers[$headerKey][0] } else { $null }

            if ($present) {
                $score += $meta.Weight
            }

            $results += [PSCustomObject]@{
                Header     = $headerKey
                Description= $meta.Name
                Status     = if ($present) { "PASS" } else { "FAIL (Missing)" }
                Value      = $val
            }
        }

        Write-Host "`nTarget: $Uri" -ForegroundColor Cyan
        Write-Host "Compliance Score: $score / 100" -ForegroundColor $(if ($score -ge 80) { "Green" } else { "Yellow" })
        
        $results | Format-Table -AutoSize
    }
    catch {
        Write-Error "Failed to reach endpoint $Uri : $_"
    }
}

# Example Usage:
# Test-HttpSecurityHeaderCompliance -Uri "https://portal.contoso.com"
```

---

### 2. Bash / cURL: Fast Terminal Inspection

Audit response headers directly from the terminal without browser DevTools:

```bash
# Fetch response headers and grep for recommended security directives
curl -s -D - -o /dev/null "https://example.com" | grep -Ei "(strict-transport|content-security|x-content-type|x-frame|referrer-policy|permissions-policy|server)"
```

---

## Related References

- [Cross-Site Scripting (XSS) & CSP](xss-defense.md) — Fine-tuning Content Security Policy directives and nonces.
- [Cross-Site Request Forgery (CSRF) & State Defense](csrf-defense.md) — Cookie flags and SameSite attributes.
- [TLS Handshake & Cipher Suite Mechanics](../networking/tls-ssl.md) — Hardening the cryptographic transport layer.
- [CIS Benchmarks & Critical Controls](../grc/cis-benchmarks.md) — System hardening baselines and audit requirements.
