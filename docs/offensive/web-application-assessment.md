---
title: Enumerate a Web Application for Technology, Versions and Weaknesses
type: workflow
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Workflow
security_domain: Application
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [web-app, enumeration, fingerprinting, recon, nmap, whatweb, wafw00f, nikto, nuclei, httpx, php-version, content-discovery, parrot-os, kali, owasp-wstg]
aliases: [enumerate a website, web app recon, find php version externally, fingerprint web server, whatweb scan, nikto scan, nuclei web scan, wafw00f, nmap http enumeration, why external scan shows no php version, tech stack fingerprinting, content discovery gobuster ffuf, parrot os web tools]
difficulty: intermediate
verified: false
---

# Enumerate a Web Application for Technology, Versions and Weaknesses
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Every command here sends traffic to a target.
> 1. Run them **only** against a host you own or are explicitly authorized to test (signed engagement,
>    in-scope bug-bounty asset, or your own lab).
> 2. Stay inside the agreed scope, rate limit, and time window; keep a log of what you ran.
> 3. Active scanners (nikto, nuclei, content discovery) are **noisy** and may trip WAFs/IPS or disrupt
>    fragile apps. Start light; escalate only as scope allows.
> 4. Treat the output as sensitive — it maps the target's weaknesses.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (Parrot OS / Kali packages) but have not
    been lab-run for this page. Confirm flags against each tool's `--help`/man page in your build.
    Remove this block when `verified: true`.

**Trigger:** you have an authorized target web application and need to know what it is built on — web
server, framework, language and versions — and where it is exposed, so you can identify weaknesses and
write them up. A common variant: *an external scan returns no PHP version even though you know it runs
PHP.*

**Goal:** work from passive identification to active enumeration using the tools shipped with
[Parrot OS](https://parrotsec.org/) (the same tools ship on Kali), capturing technology, versions,
exposed content and likely weaknesses — **enumeration and fingerprinting, not exploitation**.

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Service/port enumeration | `nmap` | Open ports, service/version banners, HTTP NSE results |
| Technology fingerprint | `whatweb`, `httpx`, `wafw00f` | Server, framework, language, CMS, WAF presence |
| Content discovery | `gobuster`, `ffuf`, `feroxbuster` | Hidden paths, admin panels, backup/info files |
| Weakness identification | `nikto`, `nuclei` | Known misconfigurations and CVE-class exposures |
| Transport review | `testssl.sh`, `curl` | TLS config, security headers |

## 0. Set the target once

```bash
TARGET="https://REPLACE-with-authorized-host.example"
HOST="REPLACE-with-authorized-host.example"
OUT="./assessment_$HOST"
mkdir -p "$OUT"
```

## 1. Service and port enumeration (nmap)

Find the web ports and grab service/version banners, then run the safe HTTP enumeration scripts:

```bash
# Service/version detection on the common web ports (-Pn: skip host discovery if ICMP is filtered)
nmap -sV -Pn -p 80,443,8080,8443 -oN "$OUT/nmap-sv.txt" "$HOST"

# Safe HTTP enumeration scripts: title, server header, methods, robots.txt, and PHP fingerprint
nmap -Pn -p 80,443 --script="http-title,http-server-header,http-headers,http-methods,http-robots.txt,http-php-version" \
  -oN "$OUT/nmap-http.txt" "$HOST"
```

`-sV` reads the raw service banner; the `http-*` scripts parse the HTTP layer. `http-php-version`
tries known PHP fingerprint hashes — it only succeeds when the server leaks enough to match.

## 2. Technology and WAF fingerprinting

```bash
# WhatWeb: server, framework, CMS, language, and often a version range (aggression level 3 = active)
whatweb -a 3 --log-brief "$OUT/whatweb.txt" "$TARGET"

# httpx: fast tech-detect, status, title, and detected technologies
httpx -u "$TARGET" -td -title -server -status-code -o "$OUT/httpx.txt"

# wafw00f: is there a WAF/CDN in front? (changes how you interpret everything else)
wafw00f "$TARGET" -o "$OUT/wafw00f.txt"
```

A WAF/CDN (Cloudflare, Akamai, AWS WAF) in front explains missing banners and altered responses — note
it before trusting any version result.

## 3. The PHP-version case: external scan shows nothing

If your **internal** tool reports the PHP version but an **external** scan does not, that is expected
behaviour, not a tool failure. The server is almost certainly hardened to not advertise it:

| Setting | Effect | Where |
| :--- | :--- | :--- |
| `expose_php = Off` | Removes the `X-Powered-By: PHP/x.y.z` header | `php.ini` |
| `ServerTokens Prod` | Apache `Server:` banner shows only `Apache` | `httpd.conf` |
| `server_tokens off;` | nginx drops the version from `Server:` | `nginx.conf` |

Your internal tool reads the version from the runtime (`php -v`, `phpversion()`, local headers); an
external scanner only sees what the server chooses to send. With exposure off, there is nothing to read.

**Step 1 — read what the server does send:**

```bash
curl -sSI "$TARGET" | grep -iE 'server|x-powered-by|set-cookie|date'
```

A `PHPSESSID` cookie confirms PHP is in use even when the version is hidden. An `X-Powered-By` line is
where the version lives when `expose_php` is on — its absence tells you exposure is disabled.

**Step 2 — look for forgotten info files (the most common real leak):**

```bash
for p in info.php phpinfo.php test.php i.php php.php _profiler/phpinfo; do
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$TARGET/$p")
  echo "$code  /$p"
done
```

A reachable `phpinfo()` page discloses the exact version, build date, and full configuration at once.

**Step 3 — let the scanners try fingerprint matching:**

```bash
nmap -Pn -p 80,443 --script=http-php-version -oN "$OUT/nmap-php.txt" "$HOST"
whatweb -a 3 "$TARGET" | tr ',' '\n' | grep -i php
```

### What to expect

When `expose_php` is **off** and server tokens are stripped, you often **cannot** obtain the exact
point release (e.g. `8.2.12`) externally — only an inference. Build the estimate by correlation:

- `Server: Apache/2.4.x (Ubuntu)` or `nginx/1.xx (Debian)` → map the distro release to the PHP build
  it ships.
- Detected framework version (WordPress, Laravel, Symfony) → its **minimum** required PHP.
- TLS stack and header ordering → coarse version bucketing.

That gap between your internal reading and the external blank is the **intended result of the
hardening** — record it as a positive finding (version disclosure is suppressed), not a dead end.

## 4. Content and path discovery

Enumerate reachable paths — admin panels, backups, `.git`, config and info files. Use a wordlist from
`seclists` (install with `sudo apt install seclists` on Parrot/Kali):

```bash
WL="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"

# ffuf: fuzz the path, filter noise, cap the rate to stay polite/in-scope
ffuf -u "$TARGET/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 -rate 50 -o "$OUT/ffuf.json"

# gobuster: directory/file brute force with common extensions
gobuster dir -u "$TARGET" -w "$WL" -x php,txt,bak,old,zip -o "$OUT/gobuster.txt"
```

Always read the freebies first — they are authoritative and zero-noise:

```bash
curl -sS "$TARGET/robots.txt"; echo
curl -sS "$TARGET/sitemap.xml" | head
curl -sS "$TARGET/.well-known/security.txt"; echo
```

## 5. Weakness identification

```bash
# Nikto: classic web-server misconfigurations, dangerous files, outdated components
nikto -h "$TARGET" -Tuning b -o "$OUT/nikto.txt"

# Nuclei: templated checks for tech, exposures, misconfigs, and known CVEs (keep severity scoped)
nuclei -u "$TARGET" -tags tech,php,exposure,misconfig -severity info,low,medium,high \
  -o "$OUT/nuclei.txt"
```

These **identify** likely issues (outdated software, exposed `.git`, default files, missing headers).
Confirm each finding manually and only exploit within an authorized, scoped engagement. The fixes are
documented under [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) and
its sibling pages (SQLi, XSS, CSRF, SSRF, headers, sessions).

## 6. Transport and header review

```bash
# TLS protocols, ciphers, certificate chain and known TLS issues
testssl.sh --quiet --color 0 "$HOST" > "$OUT/testssl.txt"

# Security headers present/missing (HSTS, CSP, X-Frame-Options, ...)
curl -sSI "$TARGET" | grep -iE 'strict-transport|content-security|x-frame|x-content-type|referrer-policy'
```

See [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md) and
[TLS & SSL Cryptography](../fundamentals/networking/tls-ssl.md) for the hardening baseline.

## 7. Record findings

Keep the raw tool output under `"$OUT"` as evidence, then summarize per finding: **what** (the weakness),
**where** (URL/port), **evidence** (the tool line), **severity**, and **fix** (link the OWASP/hardening
page). This maps directly to the reporting phase in
[Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md).

## Detect it

Every step here sends traffic to the target, and the active scanners (content discovery, nikto, nuclei)
are **loud** — a defender sees them in the access/WAF log, which is what drives the web detection content
on the [Detection](../detection/index.md) tab:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Content/path discovery brute force — bursts of 404/403 (§4) | [SPL — Web Attacks](../detection/spl/web-attacks.md) · [KQL — Web Attacks](../detection/kql/web-attacks.md) |
| Nikto / Nuclei scanning — known scanner URIs and user-agents (§5) | [SPL — Web Attacks](../detection/spl/web-attacks.md) · [KQL — Web Attacks](../detection/kql/web-attacks.md) |
| HTTP fingerprinting and info-file probing (§2–§3) | [KQL — Web Attacks](../detection/kql/web-attacks.md) |

A handful of requests blends in; hundreds of 404s from one source, scanner user-agents, or a
`phpinfo.php` probe are the signatures the access/WAF-log rules fire on.

## Harden it

The weaknesses this page surfaces close with the web-server and application controls:

- **Suppress version and banner disclosure** (§2–§3) — `expose_php = Off`, `ServerTokens Prod` /
  `server_tokens off`, and remove forgotten `phpinfo.php` files:
  [Apache & PHP Hardening](../tasks/hardening/apache-php-web-server-hardening.md) ·
  [NGINX Hardening](../tasks/hardening/nginx-web-server-hardening.md).
- **Fix the misconfigurations nikto/nuclei flag** (§5) — dangerous methods, exposed `.git`/backups,
  default files and outdated components: [Apache & PHP Hardening](../tasks/hardening/apache-php-web-server-hardening.md)
  plus the application controls in [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md).
- **Set the security headers and TLS baseline** (§6) — HSTS, CSP, `X-Content-Type-Options` and modern
  TLS: [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md) ·
  [TLS & SSL Cryptography](../fundamentals/networking/tls-ssl.md).

## Notes

- **External ≠ internal by design.** Missing version banners, altered error pages, and blocked scans
  are usually hardening (suppressed tokens, WAF) — note them as positive posture findings.
- **A WAF changes everything.** If `wafw00f` flags one, responses may be rewritten or rate-limited;
  interpret version/content results with that in mind.
- **Scope and rate discipline.** Content discovery and nikto/nuclei are loud. Cap request rates, test
  off fragile production, and never stray outside the authorized asset list.
- Install notes: `whatweb`, `nmap`, `nikto`, `wafw00f` ship on Parrot/Kali; `httpx`, `nuclei`, `ffuf`,
  `feroxbuster`, `gobuster`, `seclists`, and `testssl.sh` are one `apt install` away on those distros.

## Related

- [Offensive — Overview](index.md)
- [OSINT & Reconnaissance](../fundamentals/concepts/osint.md)
- [Port Scanning](../fundamentals/concepts/port-scanning.md)
- [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md)
- Defensive counterparts: [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) · [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md) · [Apache & PHP Hardening](../tasks/hardening/apache-php-web-server-hardening.md) · [NGINX Hardening](../tasks/hardening/nginx-web-server-hardening.md)

## External Resources & White Papers

- [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) — the methodology this page follows
- [Nmap HTTP NSE scripts](https://nmap.org/nsedoc/categories/discovery.html)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) · [wafw00f](https://github.com/EnableSecurity/wafw00f) · [Nikto](https://github.com/sullo/nikto) · [Nuclei](https://docs.projectdiscovery.io/tools/nuclei) · [httpx](https://docs.projectdiscovery.io/tools/httpx) · [ffuf](https://github.com/ffuf/ffuf) · [testssl.sh](https://testssl.sh/)
- [PHP `expose_php` directive](https://www.php.net/manual/en/ini.core.php#ini.expose-php)
