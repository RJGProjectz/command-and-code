---
title: API Surface Recon Tool (scope- and rate-limit-aware)
type: tool
platforms: [Linux]
languages: [Bash]
tasks: [Assessment]
category: Tool
security_domain: Application
author: RJGProjectz
date_created: 2026-10-21
last_updated: 2026-10-21
tags: [web-api, rest, graphql, openapi, swagger, api-docs, endpoint-discovery, introspection, rate-limiting, scope-guard, ndjson, enumeration, api-recon]
aliases: [api surface recon, api discovery script, find openapi swagger spec, graphql introspection tool, rate limited api enumeration, scope aware api recon, FUNC_BASH_GET_API_SURFACE]
difficulty: intermediate
verified: false
---

# API Surface Recon Tool (scope- and rate-limit-aware)
> **Created**: 2026-10-21T00:00:00Z
> **Last Modified**: 2026-10-21T00:00:00Z
> **Author**: RJGProjectz

> [!NOTE]
> **Enumeration only.** `scripts/bash/FUNC_BASH_GET_API_SURFACE.sh` performs read-only GET probes plus a
> single standard GraphQL introspection query. It never brute-forces authorization, enumerates object
> IDs, or sends a state-changing request. The authorization and abuse tests (BOLA/IDOR, BFLA, rate
> limits) are **manual** steps in [Web API Assessment](web-api-assessment.md) — by design, not omission.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    The script is written against the documented behaviour of its tools and APIs and is syntax-checked,
    but has not been lab-run end to end for this page. Confirm it on your Kali/Parrot build before
    relying on the output. Remove this block when `verified: true`.

> [!CAUTION]
> **Authorized use only — this contacts the target directly.** Unlike the strictly passive
> [Passive Web OSINT Tool](passive-web-osint.md), this script sends requests to the API host. Run it
> only against an API you own or are explicitly authorized to test, inside the agreed scope, rate and
> time window — see [Cyber Law](../fundamentals/concepts/cyber-law.md).

**What it does:** given one authorized API base URL, it maps the surface with a hard request-rate cap
and a strict origin guard, then writes a human summary and machine-readable NDJSON. Two safety
properties are built in, not optional:

- **Rate cap.** Every probe is throttled to `--rate` requests/second (default 2); the script sleeps
  `1/rate` between calls.
- **Scope guard.** The target's scheme + host[:port] is locked at start; any URL that would leave that
  origin is skipped with a warning, and redirects are not followed off-origin.

| Stage | What it returns | How |
| :--- | :--- | :--- |
| Spec discovery | OpenAPI/Swagger/api-docs location, if exposed | GET the usual spec paths |
| Root discovery | Which API roots respond (`/api`, `/api/v1`, `/graphql`, ...) | GET each root |
| Endpoint listing | Documented `METHOD /path` pairs | Parse an exposed OpenAPI spec with `jq` |
| GraphQL schema | Whether introspection is enabled, and the type list | One standard introspection query |
| Posture headers | `WWW-Authenticate`, CORS origin, rate-limit headers | Read response headers |

## Usage

```bash
# Minimal — summary to the terminal, evidence + NDJSON under ./apisurface_<timestamp>/
./scripts/bash/FUNC_BASH_GET_API_SURFACE.sh https://api.example.com

# Slower (1 req/s), authenticated with an engagement-issued token, both outputs
./scripts/bash/FUNC_BASH_GET_API_SURFACE.sh https://api.example.com --rate 1 --token "$TOKEN" --format both

# Extra auth header, skip the GraphQL probe, custom output dir
./scripts/bash/FUNC_BASH_GET_API_SURFACE.sh https://api.example.com \
  --header 'X-API-Key: REPLACE' --no-graphql -o ./recon
```

| Flag | Effect |
| :--- | :--- |
| `TARGET` (positional) | In-scope API base URL (required); the origin is locked to it |
| `-o, --out DIR` | Evidence + NDJSON directory (default `./apisurface_<date>`) |
| `--rate N` | Max requests/second (default `2`) — the throttle |
| `--token TOKEN` | Engagement-issued bearer token (sent as `Authorization: Bearer`) |
| `--header 'H: V'` | Extra header, repeatable (e.g. an API-key header) |
| `--no-graphql` | Skip the GraphQL endpoint probe and introspection query |
| `--format text\|json\|both` | stdout format; NDJSON is always written to `results.ndjson` |
| `-h, --help` | Usage |

## Output

```text
apisurface_<date>/
├── results.ndjson              # one record per probe + a final summary record
├── openapi.json                # the fetched spec, when one was exposed
├── endpoints.txt               # METHOD /path pairs parsed from the spec
└── graphql-introspection.json  # schema, when introspection was enabled
```

Every probe record shares one schema; the run ends with a `kind:"summary"` record:

```json
{ "kind": "root", "target": "https://api.example.com", "scanned": "2026-10-21T00:00:00-06:00",
  "url": "https://api.example.com/api/v1", "path": "/api/v1", "status": 401,
  "content_type": "application/json", "www_authenticate": "Bearer realm=\"api\"",
  "cors_allow_origin": "*", "rate_limit_header": "x-ratelimit-remaining: 59" }
{ "kind": "summary", "target": "https://api.example.com", "scanned": "2026-10-21T00:00:00-06:00",
  "openapi_spec": "openapi.json", "documented_endpoints": 42, "graphql_introspection": "enabled" }
```

Triage straight from NDJSON with `jq` — e.g. every route that answered without demanding auth, or a
wildcard CORS policy:

```bash
jq -r 'select(.kind!="summary" and .status==200) | .path' apisurface_*/results.ndjson
jq -r 'select(.cors_allow_origin=="*") | .path' apisurface_*/results.ndjson
```

## Requirements

`curl` and `jq` are required (both ship on Kali/Parrot; `sudo apt install jq`). `awk` and `sed` are in
coreutils/base. No API key is needed for the keyless discovery; `--token` is only for authenticated
surface mapping.

## Notes

- **Safe by construction.** The rate cap and scope guard cannot be switched off — if you need faster or
  wider probing, that is a deliberate, scoped decision for a different tool, not a flag here.
- **Discovery, not testing.** The script finds and documents the surface; the authorization and abuse
  verification is manual and account-driven in the workflow page, so it stays inside scope.
- **Evidence first.** Raw spec and introspection responses are kept so a finding traces back to exactly
  what the API returned, which matters for reporting.

## Detect it

The probe sweep is visible to the defender as a short burst of requests across many paths from one
client — the pattern the [Detection](../detection/index.md) tab hunts for:

- [SPL Network and DNS Hunting](../detection/spl/network-dns.md) · [KQL Network Event Hunting](../detection/kql/network-events.md) — endpoint/root sweeps and spec probing.
- [Splunk — Brute Force Success Correlation](../detection/spl/brute-force.md) — when authenticated probing produces an auth-failure burst.

## Related

- [Offensive — Overview](index.md)
- [Web API Assessment](web-api-assessment.md) — the workflow this tool feeds (§1)
- [Web Application Assessment](web-application-assessment.md) — fingerprint the serving app
- [Passive Web OSINT Tool](passive-web-osint.md) — the **passive** counterpart (never touches the target)
- Reference: [Access Control Models](../fundamentals/concepts/access-control-models.md) · [Session Management & Cookie Security](../fundamentals/web-apps/session-management.md)

## External Resources & White Papers

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html) · [GraphQL introspection](https://graphql.org/learn/introspection/)
