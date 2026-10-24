---
title: Assess a Web API for Endpoints, Authorization Flaws and Abuse
type: workflow
platforms: [Linux]
languages: [Bash, HTTP]
tasks: [Assessment]
category: Workflow
security_domain: Application
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [web-api, rest, graphql, openapi, swagger, idor, bola, bfla, broken-object-level-authorization, authz, authentication, rate-limiting, enumeration, api-recon, owasp-api-top-10, parrot-os, kali]
aliases: [web api assessment, rest api enumeration, graphql introspection, openapi swagger discovery, find api endpoints, idor testing, broken object level authorization, bola bfla, api authz testing, api rate limit testing, enumerate graphql schema, owasp api top 10]
difficulty: intermediate
verified: false
---

# Assess a Web API for Endpoints, Authorization Flaws and Abuse
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **AUTHORIZED TESTING ONLY — VALIDATE BEFORE EXECUTION**
> Every request here goes to a live API that belongs to someone.
> 1. Run them **only** against an API you own or are explicitly authorized to test (signed engagement,
>    in-scope bug-bounty asset, or your own lab).
> 2. Stay inside the agreed scope, rate limit, and time window; keep a log of every request.
> 3. Authorization testing touches **other users' data by design**. Use only accounts and object IDs
>    the engagement provides; never read, alter, or exfiltrate real third-party records.
> 4. APIs often sit in front of production databases — a careless write or a loop without a rate cap
>    can corrupt data or cause an outage. Read first; never send state-changing calls outside scope.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Commands are written against the tools' documented syntax (Parrot OS / Kali packages) but have not
    been lab-run for this page. Confirm flags against each tool's `--help`/man page in your build.
    Remove this block when `verified: true`.

**Trigger:** you have an authorized target that exposes an HTTP API — a REST service, a GraphQL
endpoint, or a mobile/SPA backend — and need to map its surface and test whether its **authorization**
holds, as distinct from fingerprinting the web application that serves the HTML. The classic finding:
*the UI hides a record, but the API returns it to any authenticated user who changes the ID.*

**Goal:** discover the API's endpoints and schema, understand its authentication model, then test the
controls the [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
calls out first — broken object-level authorization (BOLA/IDOR), broken function-level authorization
(BFLA), and missing rate limits — **as enumeration and verification, not exploitation**. For
fingerprinting the serving web app (server, framework, CMS, content discovery) use
[Web Application Assessment](web-application-assessment.md); this page starts where that one ends.

| Stage | Tools | What you learn |
| :--- | :--- | :--- |
| Spec & root discovery | `curl`, `ffuf`, `FUNC_BASH_GET_API_SURFACE.sh` | OpenAPI/Swagger spec, API roots, GraphQL endpoint |
| Endpoint enumeration | OpenAPI spec, `kiterunner`, Postman/Burp | Documented and undocumented routes and methods |
| GraphQL schema | introspection query, `graphql-cog`/`clairvoyance` | Types, queries, mutations, hidden fields |
| Auth model | `curl`, `jwt_tool` | Scheme (Bearer/JWT/API key/cookie), token structure |
| Authorization testing | two accounts + `curl`/Burp Repeater | BOLA/IDOR, BFLA, mass assignment |
| Abuse / rate limits | `curl` loop, `ffuf -rate` | Throttling, lockout, resource exhaustion exposure |

## 0. Set the target once

```bash
API="https://REPLACE-with-authorized-host.example"   # base URL, in scope
OUT="./api_assessment_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"
# Tokens the engagement issued you (never a real user's). Two low-priv accounts enable authz testing.
TOKEN_A="REPLACE-account-A-token"
TOKEN_B="REPLACE-account-B-token"
```

## 1. Discover the spec and API roots

A machine-readable spec is the fastest, lowest-noise map of an API — enumerate the usual locations
first. The companion tool [`FUNC_BASH_GET_API_SURFACE.sh`](api-surface-recon-tool.md) automates this
step with a rate cap and NDJSON output; the raw probes are below so you know what it does.

```bash
# Common spec / docs / root locations (read-only GETs)
for p in openapi.json openapi.yaml swagger.json swagger.yaml \
         v3/api-docs api-docs swagger/v1/swagger.json \
         .well-known/openapi graphql graphql/console playground \
         api api/v1 api/v2 api/latest; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$API/$p")
  echo "$code  /$p"
done
```

If a spec responds `200`, pull it — it lists every documented path, method, parameter and auth scheme:

```bash
curl -sS "$API/openapi.json" -o "$OUT/openapi.json"
# List path + method pairs from the spec
jq -r '.paths | to_entries[] | .key as $p | .value | keys[] | "\(ascii_upcase) \($p)"' \
  "$OUT/openapi.json" 2>/dev/null | sort -u | tee "$OUT/endpoints.txt"
```

No spec exposed? Brute-force API routes with an API-specific wordlist (routes, not web content):

```bash
WL="/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
ffuf -u "$API/FUZZ" -w "$WL" -mc 200,201,400,401,403,405 -rate 30 -o "$OUT/ffuf-api.json"
# kiterunner is purpose-built for API route discovery from Swagger/route wordlists
kr scan "$API" -w /usr/share/seclists/Discovery/Web-Content/api/ -x 20 -j "$OUT/kr.json"
```

`400`/`401`/`403`/`405` are **signal, not noise** for an API: they confirm a route exists but needs a
body, auth, or a different method. Keep them.

## 2. Enumerate the API type and schema

### REST

Walk each discovered route with the methods the spec (or `405`/`Allow:` headers) reveal. Read the
`Allow` header rather than guessing verbs:

```bash
curl -sS -X OPTIONS "$API/api/v1/users" -D - -o /dev/null | grep -i '^allow:'
```

### GraphQL

GraphQL exposes one endpoint and a typed schema. If **introspection** is enabled, it hands you the
entire schema — the canonical enumeration step:

```bash
curl -sS "$API/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}' \
  | tee "$OUT/graphql-introspection.json" | jq '.data.__schema.types[].name' 2>/dev/null
```

Introspection disabled? Tools like [`clairvoyance`](https://github.com/nikitastupin/clairvoyance) infer
the schema from error messages (field suggestions) — still enumeration, no exploitation. Record whether
introspection was on as a posture finding either way.

## 3. Understand the authentication model

Identify **how** the API authenticates before testing **whether** it authorizes. Compare an
unauthenticated call to an authenticated one:

```bash
# Unauthenticated — what does it leak, and which header does it demand back?
curl -sS -D - -o /dev/null "$API/api/v1/me"           # look at WWW-Authenticate, 401 vs 403
# Authenticated
curl -sS "$API/api/v1/me" -H "Authorization: Bearer $TOKEN_A" | jq .
```

If the token is a **JWT**, decode (never trust) its claims and inspect the algorithm — `alg: none`,
weak signing, or a long/absent expiry are posture findings:

```bash
# Decode header + payload only (no secret needed); jwt_tool ships on Kali/Parrot
jwt_tool "$TOKEN_A"
# or by hand:
echo "$TOKEN_A" | cut -d. -f1,2 | tr '.' '\n' | while read -r seg; do
  echo "$seg==" | base64 -d 2>/dev/null | jq . ; done
```

Note the scheme (Bearer/JWT, opaque Bearer, `X-API-Key`, session cookie), where the token is accepted
(header vs query — a token in the URL is itself a finding), and the token lifetime.

## 4. Authorization testing — the core of an API assessment

This is where APIs fail most often and where the UI gives no cover. Use **two** authorized accounts so
every test stays inside scope.

### 4a. Broken Object-Level Authorization (BOLA / IDOR)

Fetch an object as account **A**, then request **A's object id while authenticated as B**. If B gets
A's data, object-level authorization is broken ([API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)):

```bash
# As A: note an object id you legitimately own
curl -sS "$API/api/v1/orders" -H "Authorization: Bearer $TOKEN_A" | jq '.[0].id'   # -> e.g. 1001

# As B: request A's id. Expect 403/404. A 200 with A's data is a BOLA finding.
curl -sS -w '\n%{http_code}\n' "$API/api/v1/orders/1001" -H "Authorization: Bearer $TOKEN_B"
```

Also test **unauthenticated** access to the same object, and predictable-id enumeration across a
**small, in-scope** range only (never a bulk scrape of real records):

```bash
for id in 1000 1001 1002; do
  printf '%s -> ' "$id"
  curl -sS -o /dev/null -w '%{http_code}\n' "$API/api/v1/orders/$id"   # no token at all
done
```

### 4b. Broken Function-Level Authorization (BFLA)

Can a low-privilege account reach an **admin** function? Call the privileged route with the normal-user
token ([API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)):

```bash
# Admin-only route, called with a standard-user token — expect 403.
curl -sS -w '\n%{http_code}\n' -X GET "$API/api/v1/admin/users" -H "Authorization: Bearer $TOKEN_A"
# And the forbidden verb on an allowed route (read allowed, delete should not be):
curl -sS -w '\n%{http_code}\n' -X DELETE "$API/api/v1/orders/1001" -H "Authorization: Bearer $TOKEN_A"
```

### 4c. Mass assignment / excessive data exposure (read-only checks)

Does a response return more fields than the UI shows (tokens, roles, internal flags)? That is
excessive data exposure — a read-only observation:

```bash
curl -sS "$API/api/v1/me" -H "Authorization: Bearer $TOKEN_A" | jq 'keys'
```

Flag mass-assignment **candidates** (an `isAdmin`/`role` field appearing in a GET) in the report rather
than attempting to escalate; actually submitting a privileged write belongs in a scoped, authorized
exploitation phase, not this enumeration pass.

## 5. Rate-limit and abuse exposure

Missing rate limits ([API4:2023, Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/))
let one client exhaust the backend or brute an endpoint. Test the **presence of throttling**, not a
denial-of-service — a short, capped burst against a read endpoint:

```bash
# 20 quick GETs; look for a 429 and Retry-After / X-RateLimit-* headers appearing
for i in $(seq 1 20); do
  curl -sS -o /dev/null -w '%{http_code} ' "$API/api/v1/me" -H "Authorization: Bearer $TOKEN_A"
done; echo
curl -sS -D - -o /dev/null "$API/api/v1/me" -H "Authorization: Bearer $TOKEN_A" \
  | grep -iE 'x-ratelimit|retry-after|ratelimit'
```

No `429` and no rate-limit headers after a burst is a finding. **Stop at the first `429`** — you have
your answer; continuing is a DoS and out of scope.

## 6. Record findings

Keep raw responses under `"$OUT"` as evidence, then summarize per finding: **what** (e.g. BOLA on
`/orders/{id}`), **where** (method + path), **evidence** (the request/response pair and status),
**severity**, and **fix** — link the control page:

- Authorization logic → [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](../fundamentals/concepts/access-control-models.md)
- Tokens, cookies, session lifetime → [Session Management & Cookie Security](../fundamentals/web-apps/session-management.md)
- Broader web classes (injection, SSRF, headers) → [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md)

This maps to the reporting phase in
[Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md).

## Detect it

The authorization probing and endpoint sweeps above are **visible to the defender** — the same requests
drive detection content on the [Detection](../detection/index.md) tab. Pair each technique with what
catches it:

| Offensive technique here | Detect it with |
| :--- | :--- |
| Burst of `401`/`403` across accounts (BOLA/BFLA, auth probing) | [Splunk — Brute Force Success Correlation](../detection/spl/brute-force.md) |
| Endpoint/route brute force, spec probing, rate-limit bursts | [SPL Network and DNS Hunting](../detection/spl/network-dns.md) · [KQL Network Event Hunting](../detection/kql/network-events.md) |

A real client never walks `/orders/{id}` sequentially or flips tokens between requests — those are the
exact patterns the defender hunts for.

## Harden it

Every finding on this page maps to a control:

- **Enforce object- and function-level authorization server-side** (BOLA/BFLA, §4) — check ownership on
  every request, never trust an ID from the client: [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](../fundamentals/concepts/access-control-models.md).
- **Harden tokens and sessions** (auth model, §3) — short lifetimes, validated signatures/audience, no
  secrets in the client: [Session Management & Cookie Security](../fundamentals/web-apps/session-management.md).
- **Rate-limit and shield at the edge** (abuse exposure, §5) — put the API behind a hardened reverse
  proxy that caps request rate and body size: [Nginx Web-Server Hardening](../tasks/hardening/nginx-web-server-hardening.md).
- **Close the broader web classes** (injection, SSRF, headers surfaced in §1–§2) —
  [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md).

## Notes

- **The UI is not the API.** Controls enforced in the front end mean nothing if the API re-checks
  nothing; always test the API directly, not through the browser.
- **BOLA is the #1 API risk.** Most real API findings are object-level authorization, not injection —
  spend the time in §4.
- **Scope and rate discipline.** ID enumeration and rate-limit tests are the easiest way to cause harm.
  Keep ranges tiny and in-scope, stop at the first `429`, and never send state-changing verbs outside
  the authorized account's own objects.
- Install notes: `curl`, `jq`, `ffuf`, `jwt_tool` ship on or `apt install` onto Parrot/Kali;
  `kiterunner` (`kr`) and `clairvoyance` are separate installs.

## Related

- [Offensive — Overview](index.md)
- [Web Application Assessment](web-application-assessment.md) — fingerprint the serving app first
- [API Surface Recon Tool](api-surface-recon-tool.md) — automates §1 with a rate cap and NDJSON
- [Passive Web OSINT Tool](passive-web-osint.md) — find API hostnames before you touch them
- Reference: [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) · [Access Control Models](../fundamentals/concepts/access-control-models.md) · [Session Management & Cookie Security](../fundamentals/web-apps/session-management.md)

## External Resources & White Papers

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — the methodology this page follows
- [OWASP Web Security Testing Guide — API testing](https://owasp.org/www-project-web-security-testing-guide/)
- [kiterunner](https://github.com/assetnote/kiterunner) · [jwt_tool](https://github.com/ticarpi/jwt_tool) · [clairvoyance](https://github.com/nikitastupin/clairvoyance) · [ffuf](https://github.com/ffuf/ffuf)
- [GraphQL introspection](https://graphql.org/learn/introspection/)
