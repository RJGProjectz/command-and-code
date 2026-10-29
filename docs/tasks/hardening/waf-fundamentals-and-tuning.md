---
title: WAF Fundamentals & Tuning
type: entry
platforms: [Linux, AWS, Azure]
languages: [Bash]
tasks: [Hardening, Assurance, Detection Engineering]
category: Web Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [waf, modsecurity, coraza, owasp-crs, web-application-firewall, rule-tuning, false-positive, waf-bypass, anomaly-scoring, paranoia-level, request-smuggling, encoding-evasion, cloud-waf, aws-waf, azure-appgw-waf]
aliases: [WAF deployment, ModSecurity configuration, Coraza WAF, OWASP Core Rule Set, CRS tuning, paranoia level, WAF false positive exclusion, WAF bypass defense, encoding evasion, HTTP request smuggling WAF, cloud WAF AWS Azure, WAF anomaly scoring]
difficulty: advanced
verified: true
last_verified: 2026-10-28
---

# WAF Fundamentals & Tuning
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **VALIDATE IN STAGING BEFORE DEPLOYING TO PRODUCTION**
> A misconfigured WAF in blocking mode can reject legitimate traffic.
> 1. Always start in **detection-only** mode; switch to blocking after a tuning period.
> 2. Maintain a rollback plan (disable WAF or switch to detection mode) before enabling blocking.
> 3. Never suppress rules wholesale; tune with targeted exclusions.

Comprehensive reference on WAF deployment models, inspection engine mechanics, OWASP Core Rule Set (CRS) anatomy and paranoia levels, tuning lifecycle, and defense against evasion techniques.

---

## 1. WAF Deployment Models

| Model | Architecture | Pros | Cons |
| :--- | :--- | :--- | :--- |
| **Inline reverse proxy** | WAF sits between client and origin (ModSecurity in NGINX, Coraza, HAProxy with coraza-proxy-wasm) | Full L7 visibility; blocks before origin | Adds latency hop; single point of failure if not HA |
| **Cloud edge / CDN** | WAF enforced at CDN PoP (Cloudflare WAF, AWS CloudFront+WAF, Azure Front Door+WAF) | Global anycast PoPs; absorbs volumetric attacks far from origin | Opaque rule engine; custom rules limited; cost per rule evaluation |
| **Application gateway** | Regional load-balancer + WAF tier (Azure Application Gateway WAF, AWS ALB + AWS WAF) | Managed patching; native SIEM integration | Regional (not global edge); throughput limits |
| **Agent / daemon-based** | WAF agent in-process (PowerWAF/libinjection linked to app) or sidecar container in a service mesh | Zero additional network hop | Per-language SDK; updates coupled to app deploys |
| **Out-of-band (passive)** | Traffic mirrored to WAF for analysis without inline inspection (SPAN port, packet broker) | Zero impact on production traffic | Detection only; cannot block in real time |

**Selection guidance:**
- Public internet applications with volumetric DDoS risk → Cloud edge WAF.
- Internal APIs and microservices → Inline reverse proxy (Coraza) or agent-based.
- Regulated industries with audit requirements → Inline proxy with full audit logging.

---

## 2. Inspection Engine Mechanics

### Signature / regex pattern matching

The WAF applies a set of PCRE regular expressions to:
- Request URI, query string, and path.
- Request body (JSON, XML, multipart, URL-encoded form).
- Request headers (Cookie, User-Agent, Content-Type, etc.).
- Response body (some WAFs; expensive due to buffering).

Signature matching is fast and precise for known attack patterns but generates false positives on legitimate data that resembles attack patterns (e.g., a SQL column named `users` triggers SQLi rules).

### Anomaly scoring model (OWASP CRS default)

Rather than blocking on the first signature match, CRS accumulates a per-request **anomaly score**. Each matching rule adds points (typically 5 for CRITICAL, 4 for ERROR, 3 for WARNING, 2 for NOTICE). The request is blocked only if the total score exceeds a threshold (default 5 in paranoia level 1, meaning a single CRITICAL hit blocks).

```
Request arrives →
  Rule 942100 matches (SQL injection pattern, score +5) →
  Rule 942200 matches (SQL injection variant, score +5) →
  Total score = 10 → exceeds threshold 5 → BLOCK
```

### Paranoia levels (PL)

CRS has four paranoia levels that trade false-negative rate for false-positive rate:

| PL | Ruleset activated | False positive rate | Use case |
| :--- | :--- | :--- | :--- |
| **PL1** | Most aggressive SQLi/XSS/LFI/RFI rules; generic attack patterns | Low | Good default for most production deployments |
| **PL2** | Additional SQLi variations, header injection, abnormal HTTP | Medium | High-security applications with tuning capacity |
| **PL3** | Further SQLi/XSS variations, JavaScript encoding | High | Security-critical applications with extensive tuning |
| **PL4** | Experimental/near-zero false-negative rules | Very high | Lab or test only; extremely high FP rate |

---

## 3. Coraza / ModSecurity Configuration

[Coraza](https://coraza.io/) is the modern, OWASP-maintained Go implementation of the ModSecurity ABI. It runs as NGINX/Caddy/Envoy middleware.

### Minimal Coraza + CRS setup (NGINX)

```nginx
# /etc/nginx/nginx.conf — load the Coraza module
load_module modules/ngx_http_modsecurity_module.so;

http {
    modsecurity on;
    modsecurity_rules_file /etc/coraza/coraza.conf;
}
```

```apache
# /etc/coraza/coraza.conf
Include /etc/coraza/crs/coraza.conf-recommended
Include /etc/coraza/crs/crs-setup.conf
Include /etc/coraza/crs/rules/*.conf

# Core settings
SecRuleEngine DetectionOnly     # Start in detection; switch to On to block
SecRequestBodyAccess On
SecResponseBodyAccess Off       # Disable response body inspection (high CPU cost)
SecRequestBodyLimit 13107200    # 12.5 MB max body
SecRequestBodyNoFilesLimit 65536

# Audit log
SecAuditEngine RelevantOnly     # Log only triggered rules
SecAuditLogParts ABIJDEFHZ
SecAuditLog /var/log/coraza/modsec_audit.log
```

### crs-setup.conf paranoia level

```apache
# /etc/coraza/crs/crs-setup.conf
SecAction \
    "id:900000,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    tag:'OWASP_CRS',\
    ver:'OWASP_CRS/4.0.0',\
    setvar:tx.blocking_paranoia_level=1,\
    setvar:tx.detection_paranoia_level=2,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"
```

- `blocking_paranoia_level=1` — only PL1 rules evaluate for blocking decisions.
- `detection_paranoia_level=2` — PL2 rules evaluate and log anomaly score contributions but do not block on their own.
- This pattern lets you tune PL2 rules before promoting to blocking.

---

## 4. CRS Ruleset Anatomy

CRS rules are grouped by attack category under `REQUEST-*.conf` files:

| File | Category | Example Rule IDs |
| :--- | :--- | :--- |
| `REQUEST-913-SCANNER-DETECTION.conf` | Vulnerability scanner fingerprinting | 913100–913110 |
| `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | HTTP protocol violations | 920170–920490 |
| `REQUEST-921-PROTOCOL-ATTACK.conf` | HTTP request smuggling, splitting | 921110–921180 |
| `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | Local file inclusion | 930100–930130 |
| `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | Remote file inclusion | 931100–931130 |
| `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | OS command injection | 932100–932180 |
| `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | Cross-site scripting | 941100–941370 |
| `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | SQL injection | 942100–942550 |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | Session fixation | 943100–943120 |
| `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | Java serialisation, Log4Shell | 944100–944240 |

**Reading a CRS rule:**
```apache
SecRule ARGS "@rx (?:union\s+(?:all|distinct|[(!@]+?)\s*[([]+?\s*select|(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:\w+\s+){0,2}(?:from|into|table|database|tablespace|procedure|function|view|index|type|user|session|status|database))"
    "id:942100,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase,t:replaceComments,\
    msg:'SQL Injection Attack Detected via libinjection',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/4.0.0',\
    severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score=+%{tx.critical_anomaly_score}'"
```

Key elements:
- `ARGS` — operator target (all query string + body parameters).
- `@rx ...` — PCRE regex operator.
- `t:urlDecodeUni,t:htmlEntityDecode,t:lowercase` — **transformation chain** (normalisation before matching).
- `severity:'CRITICAL'` — contributes `tx.critical_anomaly_score` (5 points by default) to the request anomaly score.
- `block` — signals the rule engine to block if anomaly threshold is exceeded.

---

## 5. Tuning Lifecycle

### Phase 1: Baseline (detection-only, 2–4 weeks)

Deploy WAF in `DetectionOnly` mode. Collect audit logs. Identify the top false-positive sources:

```bash
# Parse ModSec audit log — find top triggered rule IDs
grep "id \"" /var/log/coraza/modsec_audit.log | \
    grep -oP 'id "\K[0-9]+' | sort | uniq -c | sort -rn | head -20

# Correlate rule ID with the request URI
awk '/--[a-zA-Z0-9]+-A--/,/--[a-zA-Z0-9]+-Z--/' /var/log/coraza/modsec_audit.log | \
    grep -E "(rule id|REQUEST_URI)" | paste - - | sort | uniq -c | sort -rn | head
```

### Phase 2: Targeted exclusions

Write narrowly scoped exclusions — never suppress a rule globally.

```apache
# Exclude rule 942100 for the admin upload endpoint only (path + method)
SecRule REQUEST_URI "@beginsWith /admin/upload" \
    "id:1000001,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveById=942100"

# Exclude rule 942200 for a specific parameter (the 'description' field always contains SQL keywords)
SecRuleUpdateTargetById 942200 "!ARGS:description"

# Exclude all SQLi rules for requests authenticated by a specific header (high-trust internal API)
SecRule REQUEST_HEADERS:X-Internal-Token "@streq my-secret-token" \
    "id:1000002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleRemoveByTag=attack-sqli"
```

### Phase 3: Switch to blocking mode

```apache
# Change in coraza.conf
SecRuleEngine On   # Was: DetectionOnly
```

Monitor for 429/403 spikes in access logs:
```bash
grep " 403 " /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

### Phase 4: Ongoing monitoring

- Alert on anomaly score distribution shifts (sudden increase in blocked requests from a new IP range = likely attack, or new deployment = likely FP from new endpoint).
- Review WAF audit log weekly; promote PL2 detection rules to PL1 blocking as FP rate decreases.
- Subscribe to CRS release announcements for new rules (especially CVE-driven additions like Log4Shell / Spring4Shell).

---

## 6. WAF Evasion Techniques & Bypass Defense

Understanding how attackers evade WAFs informs both rule selection and application-layer hardening.

### URL and encoding tricks

| Technique | Example (SQLi payload) | Defence |
| :--- | :--- | :--- |
| **URL encoding** | `' OR 1=1` → `%27+OR+1%3D1` | CRS applies `t:urlDecodeUni` before matching |
| **Double URL encoding** | `%27` → `%2527` | Normalisation must decode twice; `t:urlDecodeUni` handles this |
| **Hex encoding** | `'` → `\x27`, `0x27` | `t:hexDecode` transformation; ensure all transforms applied |
| **Unicode normalisation** | `ʼ` (U+02BC modifier letter) looks like `'` | `t:utf8toUnicode` → normalise to ASCII before pattern match |
| **HTML entity encoding** | `&apos;` or `&#x27;` | `t:htmlEntityDecode` in the CRS transform chain |
| **SQL comment injection** | `UNION/**/SELECT` → `UNION SELECT` | Regex accounts for comment patterns; CRS rule 942480 |
| **Case variation** | `uNiOn SeLeCt` | `t:lowercase` transform normalises before matching |
| **Null byte injection** | `payload%00.jpg` | Handled by WAF null-byte filtering; validate at app layer too |

### Chunked transfer encoding abuse

HTTP/1.1 allows request bodies split across multiple chunks. A WAF that reassembles chunks incorrectly may see a different payload than the backend.

```http
POST /api/query HTTP/1.1
Transfer-Encoding: chunked

5
' OR
7
 '1'='1
0
```

The backend receives `' OR '1'='1` (SQLi); a WAF that inspects chunks individually misses it.

**Defence:** `SecRequestBodyAccess On` with `SecRule REQUEST_HEADERS:Transfer-Encoding "chunked"` to ensure full body reassembly before inspection.

### HTTP request smuggling (CL-TE / TE-CL)

In CL-TE smuggling, the WAF interprets Content-Length while the backend honours Transfer-Encoding, causing the WAF to inspect a truncated view of the request.

```http
POST / HTTP/1.1
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: evil.example.com
```

The WAF sees a benign POST. The backend (TE-aware) processes `GET /admin`.

**Defence:**
1. Ensure WAF and backend agree on which header wins (NGINX: `proxy_http_version 1.1; proxy_set_header Connection "";` removes ambiguity).
2. Apply CRS rule 921110 (HTTP request smuggling detection).
3. Use HTTP/2 to the backend where possible (request smuggling is an HTTP/1.1 problem).

### Impedance mismatch exploits

Different parsers interpret the same input differently:
- WAF parses a JSON body and finds no injection; the app deserialises a nested path (`{"x":{"y":"payload"}}`) that the WAF's flat JSON schema misses.
- WAF parses multipart form fields in order; app parses the last duplicate field value; attacker sends `username=admin&username=attacker` — WAF checks `admin`, app uses `attacker`.

**Defence:**
- Validate request structure at the application layer independent of the WAF.
- Use `SecRequestBodyNoFilesLimit` to limit body complexity.
- Disable `multipart/form-data` on endpoints that do not need file uploads.

---

## 7. Cloud WAF Reference

### AWS WAF (CloudFront / ALB)

```bash
# Create a Web ACL with AWS Managed Rules (SQLi + XSS baseline)
aws wafv2 create-web-acl \
    --name "prod-web-acl" \
    --scope REGIONAL \
    --default-action Allow={} \
    --rules '[
        {"Name":"AWSManagedRulesCommonRuleSet","Priority":1,
         "OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":
            {"VendorName":"AWS","Name":"AWSManagedRulesCommonRuleSet"}}},
        {"Name":"AWSManagedRulesSQLiRuleSet","Priority":2,
         "OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":
            {"VendorName":"AWS","Name":"AWSManagedRulesSQLiRuleSet"}}}
    ]' \
    --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=prod-waf
```

### Azure Application Gateway WAF

```bash
# Enable WAF v2 in Prevention mode with OWASP 3.2 ruleset
az network application-gateway waf-config set \
    --resource-group myRG \
    --gateway-name myAppGW \
    --enabled true \
    --firewall-mode Prevention \
    --rule-set-type OWASP \
    --rule-set-version 3.2

# Disable a specific rule (false positive on rule 942100)
az network application-gateway waf-config set \
    --resource-group myRG \
    --gateway-name myAppGW \
    --disabled-rule-groups "REQUEST-942-APPLICATION-ATTACK-SQLI 942100"
```

---

## 8. Verification & Testing the WAF

```bash
# Verify the WAF is blocking a known SQLi pattern (detection-only: check log; blocking: expect 403)
curl -sv "https://staging.example.com/api/items?id=1'+OR+'1'='1" 2>&1 | grep "< HTTP"

# Test WAF is rejecting a scanner user-agent
curl -sv -A "sqlmap/1.0" https://staging.example.com/ 2>&1 | grep "< HTTP"

# Test XSS blocking
curl -sv "https://staging.example.com/search?q=<script>alert(1)</script>" 2>&1 | grep "< HTTP"

# Test path traversal blocking
curl -sv "https://staging.example.com/download?file=../../../../etc/passwd" 2>&1 | grep "< HTTP"

# Audit log entry for a triggered rule
grep "942100" /var/log/coraza/modsec_audit.log | tail -5
```

---

## Operational Gotchas

- **`SecResponseBodyAccess On`** doubles memory usage on large responses; keep it `Off` unless response inspection is required.
- **Paranoia level and login forms** — PL2+ frequently fires on password fields containing symbols (e.g., `p@ssw0rd!` triggers XSS rules). Add `SecRuleUpdateTargetById 941xxx !ARGS:password` exclusions before enabling PL2 on auth endpoints.
- **CRS and JSON request bodies** — CRS requires `modsecurity-recommended.conf`'s JSON body processor to be active. Without it, JSON payloads are not parsed and SQLi/XSS rules miss injections in JSON values.
- **WAF and WebSocket upgrades** — most WAFs only inspect the HTTP upgrade handshake, not subsequent WebSocket frames. Complement with application-level message validation.
- **Cloud WAF and IP reputation** — AWS/Azure managed rule groups include IP reputation lists that block Tor exit nodes and known scanners. These may trigger for legitimate privacy-conscious users; review blocking vs count-mode for IP reputation rules.

---

## Related

- [HTTP Protocol Mechanics & Browser Security Model](../../fundamentals/web-apps/http-protocol-mechanics.md)
- [Web Server & Reverse Proxy Hardening](web-server-reverse-proxy-hardening.md)
- [NGINX Web Server Hardening](nginx-web-server-hardening.md)
- [OWASP Web Top 10](../../fundamentals/web-apps/owasp-web-top-10.md)
- [Web Application Security Testing](web-app-security-testing.md)
- [Web Attack Detection — SPL](../../detection/spl/web-attacks.md)
- [Web Attack Detection — KQL](../../detection/kql/web-attacks.md)
- [Proxy Servers](../../fundamentals/concepts/proxy-servers.md)

## External Resources & White Papers

- [OWASP CRS Documentation](https://coreruleset.org/docs/)
- [Coraza WAF](https://coraza.io/docs/)
- [OWASP CRS GitHub](https://github.com/coreruleset/coreruleset)
- [HTTP Request Smuggling — PortSwigger](https://portswigger.net/web-security/request-smuggling)
- [WAF Bypass Techniques — HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/waf-bypass)
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/)
- [Azure Application Gateway WAF](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview)
