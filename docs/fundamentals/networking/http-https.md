---
title: Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers
type: entry
platforms:
  - Linux
  - Windows Server
languages:
  - Bash
  - PowerShell
tasks:
  - Investigation
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - http
  - https
  - web
  - rest
---

# Fundamentals — HTTP/HTTPS Protocol Mechanics & Headers

Hypertext Transfer Protocol (HTTP) on TCP port 80 and HTTP Secure (HTTPS) on TCP port 443 govern web content delivery, API transactions, and cloud application communication.

## 1. HTTP Methods & Semantics

| Method | Idempotent | Safe | Typical SOC / Operational Use |
| :--- | :--- | :--- | :--- |
| `GET` | Yes | Yes | Retrieve resource; query APIs; C2 beacon polling |
| `POST` | No | No | Submit data; credential transmission; data exfiltration payload |
| `PUT` | Yes | No | Replace resource; upload binary / web shell |
| `DELETE` | Yes | No | Remove resource; evidence destruction |
| `HEAD` | Yes | Yes | Retrieve headers only without body; lightweight health checks |
| `OPTIONS` | Yes | Yes | CORS pre-flight; service capability discovery |

---

## 2. Essential Security Response Headers

- `Strict-Transport-Security` (HSTS): Enforces HTTPS connections and disallows SSL stripping.
- `Content-Security-Policy` (CSP): Restricts domain sources from which scripts, styles, and frames can load (XSS defense).
- `X-Frame-Options`: Prevents clickjacking by blocking iframe rendering (`DENY` or `SAMEORIGIN`).
- `X-Content-Type-Options`: Set to `nosniff` to prevent MIME-type confusion attacks.

---

## 3. Diagnostic Commands

```bash
# Inspect response headers and SSL negotiation without downloading body
curl -Iv https://example.com

# Timing metrics (DNS, TCP handshake, TLS negotiation, TTFB)
curl -s -w "\\nDNS: %{time_namelookup}s\\nConnect: %{time_connect}s\\nTLS: %{time_appconnect}s\\nTTFB: %{time_starttransfer}s\\nTotal: %{time_total}s\\n" -o /dev/null https://example.com
```
