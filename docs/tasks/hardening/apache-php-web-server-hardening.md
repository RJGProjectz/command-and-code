---
title: Apache & PHP Web Server Hardening
type: workflow
platforms: [Linux]
languages: [Bash, HTTP]
tasks: [Hardening, Assurance, Administration]
category: Workflow
security_domain: Application
author: RJGProjectz
date_created: 2026-10-22
last_updated: 2026-10-22
tags: [apache, httpd, php, php-ini, web-server-hardening, security-headers, mod_headers, servertokens, open_basedir, disable_functions, hsts, csp, waf, defense]
aliases: [apache hardening, php hardening, php.ini security, harden apache web server, secure php configuration, apache security best practices, hide php version, hide apache version, disable_functions, open_basedir, apache security headers, website hardening best practices]
difficulty: intermediate
verified: false
---

# Apache & PHP Web Server Hardening
> **Created**: 2026-10-22T02:30:00Z
> **Last Modified**: 2026-10-22T02:30:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Verify the script integrity and test in a non-production environment.
> 2. Ensure you are in a `Test` or `Dev` environment.
> 3. Validate commands with `apachectl configtest` / `php --ini` where supported.
> 4. Never run unverified "prerequisite" commands from external links.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The directives below follow the documented behaviour of Apache httpd 2.4, PHP 8.x and the
    CIS/OWASP guidance cited at the foot of this page, but have **not** been lab-run end to end for
    this page. `disable_functions`, `open_basedir`, a strict `Content-Security-Policy` and module
    removals **can break a working application** — roll each out in staging, watch the logs, and
    confirm the app still works before production. Remove this block when `verified: true`.

This is the **defensive counterpart** to active web fingerprinting: it removes the version banners,
headers and default behaviours an attacker reads first (see
[Passive Web OSINT Tool](../../offensive/passive-web-osint.md) and
[Web Application Assessment](../../offensive/web-application-assessment.md) for what they look for),
then locks down Apache and PHP so a foothold is harder to gain and smaller in blast radius.

---

## 1. Website hardening — baseline principles

Apply these first; the Apache and PHP specifics below implement them.

| Principle | What it means in practice |
| :--- | :--- |
| **Patch & minimise** | Keep `apache2`/`httpd` and `php` current; remove modules, handlers and sample apps you do not use. Every enabled module is attack surface. |
| **Least privilege** | Apache runs as an unprivileged user (`www-data`/`apache`); web content is **not** owned by that user where it does not need write access. |
| **Default deny** | Serve only what you intend to serve — deny the filesystem root, directory listings, dotfiles and VCS folders by default. |
| **Reduce disclosure** | Strip version banners (`Server`, `X-Powered-By`) and verbose errors so recon returns nothing useful. |
| **Encrypt in transit** | TLS 1.2/1.3 only, HSTS on — see [TLS/SSL Certificate Deployment & Web Server Hardening](../administration/tls-certificate-deployment.md). |
| **Defence in depth** | Security headers, request limits, and a WAF (`mod_security` + OWASP CRS) layered on top of a hardened app. |

---

## 2. Apache httpd hardening

Place custom hardening in a dedicated conf (`/etc/apache2/conf-available/hardening.conf` on Debian,
`/etc/httpd/conf.d/hardening.conf` on RHEL) so upgrades do not overwrite it.

### 2.1 Suppress version & banner disclosure

```apache
# Report only "Apache" with no version, OS or module list; no footer on error pages.
ServerTokens Prod
ServerSignature Off

# Disable the TRACE method (Cross-Site Tracing / header reflection).
TraceEnable Off
```

### 2.2 Default-deny the filesystem, kill listings and dotfiles

```apache
# Deny everything by default; grant access only inside the document root (below).
<Directory />
    Options None
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/html>
    # -Indexes: no auto directory listing. -Includes: no SSI. -ExecCGI: no CGI here.
    Options -Indexes -Includes -ExecCGI -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Never serve .htaccess/.htpasswd, VCS metadata, or editor/backup files.
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>
<DirectoryMatch "/\.(git|svn|hg|bzr)(/|$)">
    Require all denied
</DirectoryMatch>
<FilesMatch "(\.(bak|old|orig|save|swp|inc)|~)$">
    Require all denied
</FilesMatch>
```

> Prefer `AllowOverride None` and put rules in the server config: `.htaccess` is slower and lets a
> compromised app rewrite its own security policy.

### 2.3 Remove modules you do not use

```bash
# Debian/Ubuntu — disable commonly unnecessary modules, then test and reload.
sudo a2dismod -f autoindex status userdir cgi include   # directory listings, server-status, ~user dirs, SSI
sudo apache2ctl configtest && sudo systemctl reload apache2
```

On RHEL, comment out the matching `LoadModule` lines in `/etc/httpd/conf.modules.d/`. Keep
`mod_headers`, `mod_ssl`, `mod_rewrite` (if used) and `mod_reqtimeout`.

### 2.4 Request limits & timeouts (cheap DoS resistance)

```apache
Timeout 60
KeepAliveTimeout 5
LimitRequestBody 10485760          # 10 MB cap on request bodies (tune per app)
LimitRequestFields 100
LimitRequestLine 8190

# mod_reqtimeout: drop slow-loris clients that dribble headers/body.
<IfModule mod_reqtimeout.c>
    RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
</IfModule>
```

### 2.5 Run unprivileged & restrict egress

Confirm Apache drops to a non-root user and the web user cannot write its own code:

```bash
grep -RiE '^(User|Group)' /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf 2>/dev/null
# Content read-only to the web user; writable upload dirs are the explicit exception.
sudo chown -R root:www-data /var/www/html
sudo find /var/www/html -type d -exec chmod 750 {} \;
sudo find /var/www/html -type f -exec chmod 640 {} \;
```

---

## 3. HTTP security headers in Apache (`mod_headers`)

The full header matrix, values and the NGINX/IIS equivalents live in
[HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md).
This is the **Apache** implementation of that baseline:

```apache
<IfModule mod_headers.c>
    # Force HTTPS for 2 years (only enable once HTTPS works everywhere).
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"

    # Start CSP in Report-Only, tune against violations, then switch to enforcing.
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';"

    # Strip the leak that PHP adds on every response.
    Header always unset X-Powered-By
    Header unset X-Powered-By
</IfModule>
```

---

## 4. PHP hardening (`php.ini`)

Edit the active ini (`php --ini` shows its path; often `/etc/php/8.x/apache2/php.ini` or
`/etc/php.ini`). For PHP-FPM, set these in the FPM pool / `php.ini` for that SAPI.

### 4.1 Disclosure & error handling

```ini
expose_php = Off                 ; remove "X-Powered-By: PHP/8.x"
display_errors = Off             ; never show stack traces / paths to users
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log
```

### 4.2 Disable dangerous functions & remote code loading

```ini
; Block command execution and remote file inclusion. Trim this list to what your
; app genuinely does not use — disabling a function an app calls will break it.
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,proc_nice,show_source,symlink,dl
allow_url_fopen = Off            ; stop fopen()/include() over http(s)
allow_url_include = Off          ; (deprecated, but enforce Off) blocks remote PHP includes — RFI
enable_dl = Off                  ; no loading of PHP extensions at runtime
```

### 4.3 Confine the filesystem

```ini
; Restrict every file operation to the app tree plus a scratch dir. Blocks path
; traversal and reading /etc/passwd through a file-read bug.
open_basedir = /var/www/html:/var/lib/php/sessions:/tmp
```

### 4.4 Uploads & resource caps

```ini
file_uploads = On
upload_max_filesize = 8M
post_max_size = 10M
max_file_uploads = 20
max_execution_time = 30
max_input_time = 60
memory_limit = 128M
cgi.fix_pathinfo = 0             ; stop PHP guessing paths → mitigates malicious-upload execution
```

### 4.5 Session & cookie safety

```ini
session.cookie_httponly = 1      ; JS cannot read the session cookie (XSS theft)
session.cookie_secure = 1        ; cookie only sent over HTTPS
session.cookie_samesite = "Strict"
session.use_strict_mode = 1      ; reject attacker-fixated session IDs
session.use_only_cookies = 1
session.gc_maxlifetime = 1800
```

Reload after changes:

```bash
sudo apachectl configtest && sudo systemctl reload apache2   # or restart php-fpm for the FPM SAPI
```

---

## 5. Verify it

Confirm the hardening from the outside and the config from the inside:

```bash
# 1. Banners gone? Expect "Server: Apache" with no version, and NO X-Powered-By line.
curl -sI https://example.com | grep -iE '^(server|x-powered-by):'

# 2. Security headers present? (reuse the audit one-liner from the headers entry)
curl -s -D - -o /dev/null https://example.com \
  | grep -Ei 'strict-transport|content-security|x-content-type|x-frame|referrer-policy|permissions-policy'

# 3. TRACE disabled? Expect 405 Method Not Allowed.
curl -sS -X TRACE -o /dev/null -w '%{http_code}\n' https://example.com

# 4. Directory listing off? A folder with no index should return 403, not a file list.
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/uploads/

# 5. Config sanity from the host.
sudo apachectl configtest
php -i | grep -iE 'expose_php|display_errors|allow_url_include|open_basedir|cgi.fix_pathinfo'
```

For a scored, repeatable external check, run the PowerShell header-compliance audit in
[HTTP Security Headers](../../fundamentals/web-apps/http-security-headers.md#1-powershell-automated-security-header-audit-compliance-scoring)
or point [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) at the site.

---

## Detect it

Hardening reduces the attack surface; monitoring catches what still gets tried.

- **Web attacks (SQLi, XSS, traversal, login brute-force)** → [SPL — Web Attacks](../../detection/spl/web-attacks.md) and [KQL — Web Attacks](../../detection/kql/web-attacks.md): read the `access.log` / WAF log for injection and traversal payloads and login-endpoint bursts — the directives above block them, these searches alert on the attempt.
- **Credential attacks against the login** → [SPL — Brute Force & Password Spray](../../detection/spl/brute-force.md): a spike of `401`/`403`/`302`-to-login from one source in the access log.
- **Scanning & traversal probes** → alert on bursts of `404`/`403`, requests for `/.git/`, `/.env`, `.php~` and `/../` sequences in `access.log` — all of which the rules above already block but still signal targeting.
- **Config drift** → file-integrity monitoring on `php.ini`, the hardening conf and the document root (see [Linux CIS — Filesystem Integrity & Service Hardening](linux-cis-filesystem-services.md)).

---

## Related

- [NGINX Web Server Hardening](nginx-web-server-hardening.md) — the NGINX counterpart to this page
- [SPL — Web Attacks](../../detection/spl/web-attacks.md) · [KQL — Web Attacks](../../detection/kql/web-attacks.md) — the Detect-it for what this blocks
- [HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) — full header matrix, NGINX/IIS equivalents, audit scripts
- [TLS/SSL Certificate Deployment & Web Server Hardening](../administration/tls-certificate-deployment.md) — the transport layer this page assumes
- [OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md) · [Cross-Site Scripting (XSS) & CSP](../../fundamentals/web-apps/xss-defense.md)
- [Passive Web OSINT Tool](../../offensive/passive-web-osint.md) · [Web Application Assessment](../../offensive/web-application-assessment.md) — the offensive view of what this removes
- [CIS Benchmarks & Critical Controls](../../fundamentals/grc/cis-benchmarks.md) · [Cyber Law & Authorization](../../fundamentals/concepts/cyber-law.md)

## External Resources & White Papers

- [Apache HTTP Server 2.4 — Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP ModSecurity Core Rule Set (CRS)](https://coreruleset.org/)
- [PHP Manual — Security](https://www.php.net/manual/en/security.php)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
