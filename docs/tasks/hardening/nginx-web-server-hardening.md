---
title: NGINX Web Server Hardening
type: workflow
platforms: [Linux]
languages: [Bash, HTTP]
tasks: [Hardening, Assurance, Administration]
category: Workflow
security_domain: Application
author: RJGProjectz
date_created: 2026-10-22
last_updated: 2026-10-22
tags: [nginx, web-server-hardening, security-headers, server_tokens, tls, hsts, csp, add_header, limit_req, client_max_body_size, location-deny, default-deny, reverse-proxy, waf, defense]
aliases: [nginx hardening, harden nginx, secure nginx configuration, nginx security best practices, hide nginx version, server_tokens off, nginx security headers, nginx tls hardening, nginx rate limiting, nginx deny dotfiles, nginx default server, website hardening best practices]
difficulty: intermediate
verified: false
---

# NGINX Web Server Hardening
> **Created**: 2026-10-22T00:00:00Z
> **Last Modified**: 2026-10-22T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Verify the script integrity and test in a non-production environment.
> 2. Ensure you are in a `Test` or `Dev` environment.
> 3. Validate commands with `nginx -t` before every reload.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The directives below follow the documented behaviour of NGINX (stable 1.2x), Mozilla's TLS
    guidance and the CIS/OWASP references cited at the foot of this page, but have **not** been
    lab-run end to end for this page. A strict `Content-Security-Policy`, aggressive `limit_req`
    rates and `location` deny rules **can break a working application** — roll each out in staging,
    watch the logs, and confirm the app still works before production. Remove this block when
    `verified: true`.

This is the **NGINX counterpart** to
[Apache & PHP Web Server Hardening](apache-php-web-server-hardening.md): it removes the version
banners and default behaviours an attacker reads first (see
[Passive Web OSINT Tool](../../offensive/passive-web-osint.md) and
[Web Application Assessment](../../offensive/web-application-assessment.md) for what they look for),
then locks down NGINX — as an origin server or a reverse proxy — so a foothold is harder to gain and
smaller in blast radius.

---

## 1. Website hardening — baseline principles

Apply these first; the NGINX specifics below implement them.

| Principle | What it means in practice |
| :--- | :--- |
| **Patch & minimise** | Keep `nginx` current; build/enable only the modules you use. Every module is attack surface. |
| **Least privilege** | Workers run as an unprivileged user (`www-data`/`nginx`); web content is **not** owned by that user where it does not need write access. |
| **Default deny** | Serve only configured virtual hosts — answer unmatched `Host` headers with a closed default server, and deny dotfiles, VCS folders and backups by default. |
| **Reduce disclosure** | Strip the version from the `Server` banner and remove `X-Powered-By` from upstreams. |
| **Encrypt in transit** | TLS 1.2/1.3 only, HSTS on — see [TLS/SSL Certificate Deployment & Web Server Hardening](../administration/tls-certificate-deployment.md). |
| **Defence in depth** | Security headers, request/rate limits, and a WAF (`ModSecurity` + OWASP CRS, or NGINX App Protect) layered on top. |

Put custom hardening in dedicated files under `/etc/nginx/conf.d/` (http-level) and include
server-level snippets per `server {}` block so package upgrades do not overwrite them.

---

## 2. Suppress version & banner disclosure

```nginx
# http {} context — report only "nginx" with no version on responses and error pages.
server_tokens off;
```

`server_tokens off;` removes the version from the `Server:` header and default error pages. To remove
the `Server` header entirely you need the third-party `headers-more` module
(`more_clear_headers Server;`) or NGINX Plus — stock NGINX cannot unset it. For an upstream app that
leaks `X-Powered-By`, strip it at the proxy:

```nginx
# In the location / server that proxies to the app:
proxy_hide_header X-Powered-By;
proxy_hide_header X-AspNet-Version;
```

---

## 3. Default-deny unmatched hosts, listings and dotfiles

```nginx
# http {} — a closed default server: unmatched Host headers get nothing (444 = close, no response).
server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    ssl_reject_handshake on;      # TLS 1.3+: refuse the handshake for unknown SNI
    return 444;
}
```

Inside each real `server {}` block:

```nginx
# No automatic directory listing.
autoindex off;

# Never serve dotfiles, VCS metadata, or editor/backup files.
location ~ /\.(?!well-known) {            # allow /.well-known, deny every other dotfile
    deny all;
    return 404;
}
location ~* \.(bak|old|orig|save|swp|inc|sql|git)$ {
    deny all;
    return 404;
}
```

> `return 404` rather than `403` reveals less about what exists. The `(?!well-known)` negative
> lookahead keeps ACME/`security.txt` working while denying `.git`, `.env` and friends.

---

## 4. Security headers (`add_header`)

The full header matrix, values and the Apache/IIS equivalents live in
[HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md).
This is the NGINX implementation; keep it in one snippet and `include` it per server:

```nginx
# /etc/nginx/conf.d/security-headers.conf  — included inside each server {} block.
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Start CSP in Report-Only, tune against violations, then switch to enforcing.
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';" always;
```

> **`add_header` gotcha:** a child `location`/`server` with its *own* `add_header` discards **all**
> inherited headers. Re-include the snippet in any block that adds a header of its own, or your
> security headers silently vanish on those routes.

---

## 5. TLS configuration

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;                 # let TLS 1.3 clients choose; harmless for 1.2 suites
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_session_timeout 1d;
ssl_session_cache shared:MozSSL:10m;            # ~40,000 sessions
ssl_session_tickets off;
ssl_stapling on;                                # OCSP stapling (needs resolver + trusted chain)
ssl_stapling_verify on;
```

Generate values from the [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
(Intermediate profile) and manage the certificate lifecycle on
[TLS/SSL Certificate Deployment & Web Server Hardening](../administration/tls-certificate-deployment.md).

---

## 6. Request limits, timeouts & rate limiting

Cheap DoS resistance and brute-force slowdown:

```nginx
# http {} context
client_max_body_size 10m;          # cap request body (tune per app; upload routes override)
client_body_timeout 10s;           # drop slow-loris bodies
client_header_timeout 10s;         # drop slow-loris headers
large_client_header_buffers 2 8k;
send_timeout 10s;
keepalive_timeout 15s;

# Rate-limit zones: general traffic and a tighter zone for auth endpoints.
limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
```

```nginx
# Apply in server/location:
location / {
    limit_req zone=perip burst=20 nodelay;
}
location = /login {
    limit_req zone=login burst=5 nodelay;      # 5 login attempts/min/IP, then throttle
}
```

`limit_req` throttling pairs with the login brute-force detection on
[SPL — Web Attacks](../../detection/spl/web-attacks.md) — the config slows the attack, the search
tells you it happened.

---

## 7. Run unprivileged & restrict content permissions

```bash
# Workers should run as an unprivileged user (master runs as root to bind :80/:443).
grep -E '^\s*user\s' /etc/nginx/nginx.conf          # expect: user www-data;  (or nginx)

# Content read-only to the web user; writable upload dirs are the explicit exception.
sudo chown -R root:www-data /var/www/html
sudo find /var/www/html -type d -exec chmod 750 {} \;
sudo find /var/www/html -type f -exec chmod 640 {} \;
```

For PHP behind NGINX, also apply [Apache & PHP Web Server Hardening §4 (`php.ini`)](apache-php-web-server-hardening.md#4-php-hardening-phpini)
to the PHP-FPM pool — `expose_php`, `disable_functions`, `open_basedir` and secure session cookies are
SAPI-wide, not Apache-specific.

---

## 8. Verify it

Confirm the hardening from the outside and the config from the inside:

```bash
# 1. Version hidden? Expect "Server: nginx" with no version.
curl -sI https://example.com | grep -i '^server:'

# 2. Security headers present?
curl -s -D - -o /dev/null https://example.com \
  | grep -Ei 'strict-transport|content-security|x-content-type|x-frame|referrer-policy|permissions-policy'

# 3. Dotfiles denied? Expect 404.
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/.git/config

# 4. Directory listing off? A folder with no index should return 403/404, not a file list.
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/uploads/

# 5. Unknown vhost closed? A bogus Host should get no response (curl: empty reply).
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Host: not-a-real-vhost' https://example.com/ || true

# 6. Config sanity from the host.
sudo nginx -t
```

For a scored, repeatable external check, run the PowerShell header-compliance audit in
[HTTP Security Headers](../../fundamentals/web-apps/http-security-headers.md#1-powershell-automated-security-header-audit-compliance-scoring)
or point [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) at the site.

Reload after any change:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## Detect it

Hardening reduces the attack surface; monitoring catches what still gets tried.

- **Web attacks (SQLi, XSS, traversal, login brute-force)** → [SPL — Web Attacks](../../detection/spl/web-attacks.md) and [KQL — Web Attacks](../../detection/kql/web-attacks.md): read the `access.log` / WAF log for injection and traversal payloads and login-endpoint bursts — the rules above block or throttle them, these searches alert on the attempt.
- **Scanning & traversal probes** → bursts of `404`/`403`, requests for `/.git/`, `/.env`, `.php~` and `/../` sequences in `access.log` — all denied by §3 but still signal targeting.
- **Config drift** → file-integrity monitoring on the NGINX config tree and document root (see [Linux CIS — Filesystem Integrity & Service Hardening](linux-cis-filesystem-services.md)).

---

## Related

- [Apache & PHP Web Server Hardening](apache-php-web-server-hardening.md) — the Apache origin-server counterpart and the shared `php.ini` hardening
- [HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) — full header matrix, Apache/IIS equivalents, audit scripts
- [TLS/SSL Certificate Deployment & Web Server Hardening](../administration/tls-certificate-deployment.md) — the transport layer this page assumes
- [SPL — Web Attacks](../../detection/spl/web-attacks.md) · [KQL — Web Attacks](../../detection/kql/web-attacks.md) — the Detect-it for what this blocks
- [Passive Web OSINT Tool](../../offensive/passive-web-osint.md) · [Web Application Assessment](../../offensive/web-application-assessment.md) — the offensive view of what this removes
- [OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md) · [Cross-Site Scripting (XSS) & CSP](../../fundamentals/web-apps/xss-defense.md)
- [CIS Benchmarks & Critical Controls](../../fundamentals/grc/cis-benchmarks.md) · [Cyber Law & Authorization](../../fundamentals/concepts/cyber-law.md)

## External Resources & White Papers

- [NGINX — Securing and Hardening (admin guide)](https://docs.nginx.com/nginx/admin-guide/security-controls/)
- [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP ModSecurity Core Rule Set (CRS)](https://coreruleset.org/)
