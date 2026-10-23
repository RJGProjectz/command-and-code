---
title: KQL — Web Attacks (SQLi, XSS, Path Traversal & Login Brute-Force)
type: entry
platforms:
  - Azure
languages:
  - KQL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: false
difficulty: intermediate
tags:
  - kql
  - sentinel
  - web-attack
  - sqli
  - xss
  - path-traversal
  - brute-force
  - application-gateway
  - waf
  - iis
aliases:
  - detect sql injection kql
  - detect xss sentinel
  - path traversal detection kql
  - application gateway waf kql
  - web login brute force sentinel
  - w3ciislog detection
---

# KQL — Web Attacks (SQLi, XSS, Path Traversal & Login Brute-Force)

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> These are detection queries, not attack tooling. Before deploying:
> 1. Confirm the table and column names exist in your workspace (`take 10` first).
> 2. Baseline for a quiet period before turning any query into an analytics rule.
> 3. Tune thresholds and allow-lists to your traffic.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    These queries follow the documented schema of the Azure Application Gateway WAF logs
    (`AzureDiagnostics`) and `W3CIISLog`, but have **not** been lab-run against a live workspace for
    this page. Column availability depends on which diagnostic categories and log sources you
    onboard — validate against your own data before enabling. Remove this block when `verified: true`.

This is the Microsoft Sentinel / Defender equivalent of
[SPL — Web Attacks](../spl/web-attacks.md): the same SQLi, XSS, traversal and login brute-force
patterns, read from **Application Gateway WAF logs** and **IIS logs** instead of Apache/NGINX access
logs. It is the Detect-it counterpart to
[Apache & PHP Web Server Hardening](../../tasks/hardening/apache-php-web-server-hardening.md) and
[NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md), and to
[Web Application Assessment](../../offensive/web-application-assessment.md) on the offensive side.

## Log sources

| Source | Table | Notes |
| :--- | :--- | :--- |
| **Application Gateway WAF** (OWASP CRS) | `AzureDiagnostics` where `Category == "ApplicationGatewayFirewallLog"` | Highest signal — the WAF already classified the attack (`ruleId_s`, `Message`, `action_s`). |
| **Application Gateway access** | `AzureDiagnostics` where `Category == "ApplicationGatewayAccessLog"` | Raw requests (`requestUri_s`, `httpStatus_d`, `clientIP_s`). |
| **IIS** (via AMA / Log Analytics) | `W3CIISLog` | `csUriStem`, `csUriQuery`, `scStatus`, `cIP`, `csUserAgent`, `csMethod`. |

> The Application Gateway WAF log is preferred where it exists — it is pre-classified. Use the raw
> request queries when only access/IIS logs are onboarded.

- **ATT&CK**: [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/),
  [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

---

## 1. Application Gateway WAF — blocked/matched attacks

Where the WAF fronts the app, let it do the classification and summarise by source:

```kql
AzureDiagnostics
| where TimeGenerated > ago(1d)
| where Category == "ApplicationGatewayFirewallLog"
| extend Attack = tostring(Message), Rule = tostring(ruleId_s), Action = tostring(action_s)
| summarize Hits = count(), Rules = make_set(Rule, 20), Messages = make_set(Attack, 10),
            Blocked = countif(Action =~ "Blocked"), Uris = make_set(requestUri_s, 10)
          by clientIp = tostring(clientIp_s)
| where Hits >= 5 or array_length(Rules) >= 3
| order by Hits desc
```

One source tripping many **distinct** CRS rule IDs is a scanner (sqlmap/nikto/nuclei), not a stray
user.

## 2. SQL injection probes (raw request logs)

For IIS (`W3CIISLog`); the same shape works on `ApplicationGatewayAccessLog` by swapping the column
names.

```kql
W3CIISLog
| where TimeGenerated > ago(1d)
| extend decoded = tolower(url_decode(strcat(csUriStem, "?", csUriQuery)))
| where decoded matches regex @"(union(\s|/\*.*\*/)+select|select.+from|insert\s+into|\bor\b\s+\d+=\d+|'\s*(or|and)\s|--\s|;\s*(drop|update|delete)\b|sleep\s*\(|benchmark\s*\(|information_schema|xp_cmdshell)"
| summarize Hits = count(), Statuses = make_set(scStatus, 10), Paths = make_set(csUriStem, 10),
            DistinctUris = dcount(strcat(csUriStem, csUriQuery))
          by cIP, csUserAgent
| where Hits >= 3
| order by Hits desc
```

`scStatus` of `200` on these is the urgent case — the request was served, not rejected.

## 3. Cross-Site Scripting (XSS) probes

```kql
W3CIISLog
| where TimeGenerated > ago(1d)
| extend decoded = tolower(url_decode(strcat(csUriStem, "?", csUriQuery)))
| where decoded matches regex @"(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|onmouseover\s*=|<img[^>]+src|<svg|document\.cookie|string\.fromcharcode|alert\s*\(|<iframe)"
| summarize Hits = count(), Statuses = make_set(scStatus, 10), Paths = make_set(csUriStem, 10) by cIP, csUserAgent
| where Hits >= 2
| order by Hits desc
```

## 4. Path / directory traversal & sensitive-file access

```kql
W3CIISLog
| where TimeGenerated > ago(1d)
| extend decoded = tolower(url_decode(strcat(csUriStem, "?", csUriQuery)))
| where decoded matches regex @"(\.\.(/|\\)|%2e%2e|/etc/passwd|/proc/self/|boot\.ini|win\.ini|/\.git/|/\.env\b|/\.aws/|web\.config|\.(bak|old|save|swp|inc|sql)($|\?))"
| summarize Hits = count(), Statuses = make_set(scStatus, 10), Paths = make_set(csUriStem, 10) by cIP, csUserAgent
| where Hits >= 2
| order by Hits desc
```

## 5. Web login brute-force & password spray

A burst of POSTs to the login endpoint from one source. Adapt the path and the failure status to the
app (many apps answer a bad login with `200` + an error body).

```kql
W3CIISLog
| where TimeGenerated > ago(1d)
| where csMethod == "POST"
| where csUriStem has_any ("/login", "/signin", "/wp-login.php", "/admin")
| summarize Attempts = count(), Endpoints = dcount(csUriStem), Statuses = make_set(scStatus, 10)
          by bin(TimeGenerated, 5m), cIP
| where Attempts >= 20
| order by Attempts desc
```

Password **spray** (one password, many accounts) shows as one source touching many distinct usernames
at low volume — if the username is captured, pivot on `dcount(user) by cIP`. See
[KQL Logon and Identity Hunting](logon-identity.md) for the identity-log view.

---

## False positive tuning

- **Site search / CMS editors** legitimately contain `select`, `union` or markup — allow-list those
  `csUriStem` values with `where csUriStem !in (...)`.
- **Authorized scanners** you run will trip every query here — exclude tester source IPs or correlate
  against the engagement window.
- **Uptime / monitoring bots** generate repetitive login-path requests; allow-list their
  `csUserAgent` before the brute-force query alerts.
- Baseline each query over a quiet period and raise thresholds until it is silent, then lower
  carefully.

## Related

- [SPL — Web Attacks](../spl/web-attacks.md) — the same detections for Splunk / Apache & NGINX access logs
- [NGINX Web Server Hardening](../../tasks/hardening/nginx-web-server-hardening.md) · [Apache & PHP Web Server Hardening](../../tasks/hardening/apache-php-web-server-hardening.md) — the controls that block these requests
- [Web Application Assessment](../../offensive/web-application-assessment.md) · [Passive Web OSINT Tool](../../offensive/passive-web-osint.md) — the offensive view
- [HTTP Security Headers & Transport Hardening](../../fundamentals/web-apps/http-security-headers.md) · [Cross-Site Scripting (XSS) & CSP](../../fundamentals/web-apps/xss-defense.md)
- [KQL Fundamentals](fundamentals.md) · [KQL Logon and Identity Hunting](logon-identity.md)

## Sources

- [Application Gateway WAF logs](https://learn.microsoft.com/azure/web-application-firewall/ag/application-gateway-waf-metrics)
- [AzureDiagnostics table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics)
- [W3CIISLog table](https://learn.microsoft.com/azure/azure-monitor/reference/tables/w3ciislog)
- [KQL `url_decode()`](https://learn.microsoft.com/azure/data-explorer/kusto/query/urldecodefunction)
