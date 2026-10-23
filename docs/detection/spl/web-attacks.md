---
title: Splunk Detection — Web Attacks (SQLi, XSS, Path Traversal & Login Brute-Force)
type: entry
platforms:
  - Linux
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: false
difficulty: intermediate
tags:
  - splunk
  - web-attack
  - sqli
  - xss
  - path-traversal
  - brute-force
  - access-log
  - waf
  - modsecurity
aliases:
  - detect sql injection splunk
  - detect xss access log
  - path traversal detection spl
  - web login brute force splunk
  - modsecurity splunk detection
  - apache nginx access log detection
---

# Splunk Detection — Web Attacks (SQLi, XSS, Path Traversal & Login Brute-Force)

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> These are detection searches, not attack tooling. Before deploying:
> 1. Confirm the field names against your own extractions in a `Test` index.
> 2. Baseline each search for a quiet period before alerting, or it will be noisy.
> 3. Tune the thresholds and allow-lists to your traffic.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    These searches follow the documented behaviour of Splunk SPL and the standard
    `access_combined` / ModSecurity field names, but have **not** been lab-run against live
    indexes for this page. Splunk field names depend on your add-ons, props and transforms —
    validate and tune against your own data before enabling as alerts. Remove this block when
    `verified: true`.

This is the **Detect-it** counterpart to the web offensive and hardening pages: it reads the same
request patterns an attacker generates during
[Web Application Assessment](../../offensive/web-application-assessment.md) off the server's own
access and WAF logs, and pairs with
[Apache & PHP Web Server Hardening](../../tasks/hardening/apache-php-web-server-hardening.md) and
[NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md) — hardening blocks
the request, these searches tell you it was tried.

## Log sources & fields

Apache and NGINX combined access logs land in Splunk as `access_combined` (or
`access_combined_wcookie`). The common extracted fields used below:

| Field | Meaning |
| :--- | :--- |
| `clientip` / `src_ip` | Source address of the request |
| `method` | HTTP verb (`GET`, `POST`, …) |
| `uri_path` | Path portion of the request |
| `uri_query` | Query string (after `?`) |
| `status` | HTTP response code |
| `useragent` | Client User-Agent string |
| `uri` | Full request URI when `uri_path`/`uri_query` are not separately extracted |

ModSecurity (the Apache/NGINX WAF) writes its audit log separately; if onboarded as
`sourcetype=modsecurity` you also get `rule_id`, `msg` and `severity`. The last search uses it.

> URL-decode before matching so encoded payloads (`%27`, `%3C`, `..%2f`) are not missed. The searches
> below apply `urldecode()` to the inspected field.

- **ATT&CK**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/),
  [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## 1. SQL injection probes

Classic SQLi markers in the URI or query string: quote-breaking, boolean tautologies, `UNION SELECT`,
comment terminators and stacked statements.

```spl
index=web sourcetype=access_combined
| eval decoded=lower(urldecode(uri_query) . " " . urldecode(uri_path))
| regex decoded="(union(\s|\/\*.*\*\/)+select|select.+from|insert\s+into|\bor\b\s+\d+=\d+|'\s*(or|and)\s|--\s|;\s*(drop|update|delete)\b|sleep\s*\(|benchmark\s*\(|information_schema|xp_cmdshell)"
| stats count AS hits, values(status) AS statuses, values(uri_path) AS paths, dc(uri) AS distinct_uris by clientip, useragent
| where hits >= 3
| sort - hits
```

- A single hit can be a false positive (a search box containing `select`); a source generating many
  distinct SQLi-shaped URIs is targeting you.
- `status=200` on these is more urgent than `403`/`500` — the app may have processed the payload.

## 2. Cross-Site Scripting (XSS) probes

Reflected/stored XSS attempts put script and event-handler markup in parameters.

```spl
index=web sourcetype=access_combined
| eval decoded=lower(urldecode(uri_query) . " " . urldecode(uri_path))
| regex decoded="(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|<img[^>]+src|<svg|document\.cookie|String\.fromCharCode|alert\s*\(|<iframe)"
| stats count AS hits, values(status) AS statuses, values(uri_path) AS paths by clientip, useragent
| where hits >= 2
| sort - hits
```

Pair with the defensive controls on
[Cross-Site Scripting (XSS) & CSP](../../fundamentals/web-apps/xss-defense.md) — a strong CSP turns a
successful injection into a blocked one.

## 3. Path / directory traversal & sensitive-file access

Traversal sequences and requests for files a web root should never serve (`.env`, `.git`,
`/etc/passwd`, backup files).

```spl
index=web sourcetype=access_combined
| eval decoded=lower(urldecode(uri))
| regex decoded="(\.\.(\/|\\)|%2e%2e|\/etc\/passwd|\/proc\/self\/|boot\.ini|win\.ini|\/\.git\/|\/\.env\b|\/\.aws\/|web\.config|\.(bak|old|save|swp|inc|sql)(\?|$))"
| stats count AS hits, values(status) AS statuses, values(uri_path) AS paths by clientip, useragent
| where hits >= 2
| sort - hits
```

The hardening pages already deny `.git`, dotfiles and backups — a `403`/`404` here is the deny rule
working **and** a signal that someone is probing for them.

## 4. Web login brute-force & password spray

A burst of authentication attempts against the login endpoint from one source. Adapt `uri_path` and
the failure `status` to your app (many apps answer a bad login with `200` + an error body, so also
watch the ratio of login POSTs to successful `302` redirects).

```spl
index=web sourcetype=access_combined method=POST (uri_path="*/login*" OR uri_path="*/signin*" OR uri_path="*/wp-login.php" OR uri_path="*/admin*")
| bin _time span=5m
| stats count AS attempts, dc(uri_path) AS endpoints, values(status) AS statuses by _time, clientip
| where attempts >= 20
| sort - attempts
```

Password **spray** (one password, many usernames) looks different — low attempts per account but one
source touching many accounts in a window. If the username is logged, pivot on
`dc(user) by clientip`. See [Brute Force Success Correlation](brute-force.md) for the
authentication-log view of the same behaviour.

## 5. WAF (ModSecurity) rule hits — if onboarded

When ModSecurity + the OWASP Core Rule Set front the app, its audit log is the highest-signal source:

```spl
index=web sourcetype=modsecurity
| stats count AS blocks, values(msg) AS rules, dc(rule_id) AS distinct_rules, values(uri) AS uris by clientip
| where blocks >= 5 OR distinct_rules >= 3
| sort - blocks
```

One source tripping many **distinct** CRS rules is a scanner (nikto/nuclei/sqlmap), not a stray click.

---

## False positive tuning

- **Search and CMS parameters** legitimately contain words like `select`, `union` or angle brackets —
  allow-list known-good `uri_path` values (site search, WYSIWYG editors) with `NOT uri_path IN (...)`.
- **Security scanners you run** (authorized assessments) will trip every rule here — exclude your
  tester source IPs or correlate against your engagement calendar.
- **Monitoring / uptime bots** generate repetitive requests; allow-list their User-Agents before the
  brute-force search alerts on them.
- Raise the `hits`/`attempts` thresholds until a quiet baseline produces zero alerts, then lower
  carefully.

## Related

- [NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md) · [Apache & PHP Web Server Hardening](../../tasks/hardening/apache-php-web-server-hardening.md) — the controls that block these requests
- [KQL — Web Attacks](../kql/web-attacks.md) — the same detections for Microsoft Sentinel / Application Gateway WAF
- [Web Application Assessment](../../offensive/web-application-assessment.md) · [Passive Web OSINT Tool](../../offensive/passive-web-osint.md) — the offensive view of what generates these log lines
- [HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) · [OWASP Top 10 for Web Applications](../../fundamentals/web-apps/owasp-web-top-10.md)
- [SPL Fundamentals and Search Optimization](fundamentals.md) · [Brute Force Success Correlation](brute-force.md)

## External Resources & White Papers

- [OWASP ModSecurity Core Rule Set (CRS)](https://coreruleset.org/)
- [OWASP Automated Threats / Web Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Splunk Docs — `regex` command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Regex)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
