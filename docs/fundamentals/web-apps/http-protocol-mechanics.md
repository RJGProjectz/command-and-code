---
title: HTTP Protocol Mechanics & Browser Security Model
type: entry
platforms: [Linux, Windows]
languages: [Bash, PowerShell]
tasks: [Hardening, Assessment, Assurance]
category: Web Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [http, http2, http3, quic, cors, csp, hsts, sop, sri, websockets, graphql, grpc, browser-security]
aliases: [HTTP/2 multiplexing, HTTP/3 QUIC, CORS same-origin policy, Content Security Policy, browser security headers, GraphQL security, WebSocket security, gRPC security, request lifecycle]
difficulty: intermediate
verified: true
last_verified: 2026-10-28
---

# HTTP Protocol Mechanics & Browser Security Model
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

Comprehensive reference covering the HTTP protocol lifecycle across all major versions, the browser same-origin security model, and the attack surfaces introduced by modern API paradigms (REST, GraphQL, gRPC, WebSockets).

---

## 1. HTTP/1.1 — Request/Response Lifecycle

An HTTP/1.1 exchange traverses these phases before a byte of response body is delivered:

1. **DNS resolution** — client queries recursive resolver → authoritative NS returns A/AAAA → TTL cached by OS and browser.
2. **TCP handshake** — 3-way SYN/SYN-ACK/ACK; adds one round-trip time (RTT).
3. **TLS handshake** (HTTPS) — TLS 1.3 costs one additional RTT (client hello → server hello + cert + Finished → client Finished). TLS 1.2 costs two RTTs. See [TLS/SSL fundamentals](../../fundamentals/networking/tls-ssl.md).
4. **HTTP request** — client sends request line, headers, optional body:
   ```text
   GET /api/users HTTP/1.1
   Host: example.com
   Accept: application/json
   Authorization: Bearer <token>
   ```
5. **Server dispatch** — proxy/load-balancer receives the request, routes upstream, application handler executes.
6. **HTTP response** — status line, headers, body:
   ```text
   HTTP/1.1 200 OK
   Content-Type: application/json
   Cache-Control: no-store
   X-Request-ID: a1b2c3
   ```

**HTTP/1.1 limitations that drive HTTP/2 adoption:**

| Problem | Description |
| :--- | :--- |
| **Head-of-line blocking** | One TCP connection processes one request at a time; pipelining is fragile and disabled by most clients |
| **Header overhead** | Plaintext headers repeat on every request (cookies, `Authorization`, `User-Agent` sent verbatim each time) |
| **Connection limits** | Browsers open 6–8 TCP connections per origin to compensate for the lack of multiplexing |

### Verification commands

```bash
# Confirm the HTTP version in use
curl -v --http1.1 https://example.com/ 2>&1 | grep "< HTTP"

# Show raw request/response headers
curl -sv -o /dev/null https://example.com/ 2>&1 | grep -E "^[<>]"
```

---

## 2. HTTP/2 — Multiplexing & Header Compression

HTTP/2 (RFC 7540) runs over a single TLS connection and uses a binary framing layer.

### Key mechanics

| Feature | Detail |
| :--- | :--- |
| **Streams** | Each request/response pair is a numbered stream. Up to 100 concurrent streams share one TCP connection by default (`SETTINGS_MAX_CONCURRENT_STREAMS`). |
| **Multiplexing** | Frames from different streams interleave freely; a slow response on stream 5 does not block stream 7. |
| **HPACK header compression** | Static table (61 common header/value pairs) + dynamic table (per-connection LRU cache). Subsequent requests with the same headers send a single index byte instead of the full field. |
| **Server Push** | Server can proactively push resources (`PUSH_PROMISE` frame) before the client requests them. Mostly disabled now (Chrome removed support 2022). |
| **Flow control** | Per-stream and per-connection flow control windows prevent a fast sender from overwhelming a slow receiver. |

### Security considerations

- **HPACK bomb (CVE-2016-7000 class)** — crafted headers that expand the dynamic table beyond memory limits; mitigated by `http2_max_header_size` and `http2_max_field_size` limits in NGINX.
- **HTTP/2 Rapid Reset (CVE-2023-44487)** — client opens a stream then immediately sends RST_STREAM to cancel it; the server has already allocated resources. Exploit drives HTTP/2 server DoS. Patch: NGINX ≥ 1.25.3 / Apache ≥ 2.4.58.
- **Cleartext HTTP/2 (h2c)** — HTTP/2 can run without TLS. Disable `h2c` in production; always require `h2` (TLS).

```bash
# Confirm HTTP/2 is in use
curl -v --http2 https://example.com/ 2>&1 | grep "< HTTP/2"

# Inspect HTTP/2 frame-level traffic (requires Wireshark/tshark with TLS key log)
SSLKEYLOGFILE=/tmp/ssl.keys curl --http2 https://example.com/
```

---

## 3. HTTP/3 — QUIC Transport

HTTP/3 (RFC 9114) replaces TCP with QUIC (RFC 9000), a UDP-based transport that bakes in TLS 1.3.

### Packet lifecycle

```
Client                          Server
  |  Initial (ClientHello)        |
  |------------------------------>|   UDP datagram #1 (QUIC INITIAL)
  |  Initial (ServerHello+cert)   |
  |<------------------------------|
  |  Handshake (Finished)         |
  |------------------------------>|   One RTT for new connection (0-RTT possible on resume)
  |  HTTP/3 HEADERS frame         |
  |------------------------------>|
  |  HTTP/3 DATA frame            |
  |<------------------------------|
```

### Advantages over HTTP/2

| Feature | HTTP/2 (TCP) | HTTP/3 (QUIC) |
| :--- | :--- | :--- |
| **Transport HOL blocking** | Yes — TCP packet loss stalls all streams | No — stream-level loss isolation |
| **Connection migration** | No — IP change breaks TCP connection | Yes — `Connection ID` persists across IP changes (e.g., Wi-Fi → LTE) |
| **0-RTT resumption** | TLS 1.3 session tickets (TCP RTT still needed) | True 0-RTT: first application data in initial datagram |
| **Handshake latency** | 1 RTT TLS + 1 RTT TCP = 2 RTTs (new) | 1 RTT (new), 0 RTT (resumed) |

### 0-RTT replay risk
`0-RTT` data is not replay-safe. Servers MUST treat 0-RTT requests as potentially replayed; do not perform state-changing operations on them. Set `early_data off` for POST/PUT endpoints.

### Alt-Svc advertisement
HTTP/3 is discovered via the `Alt-Svc` response header from an HTTP/1.1 or HTTP/2 connection:
```text
Alt-Svc: h3=":443"; ma=86400
```

```bash
# Check if a server advertises HTTP/3
curl -sv --http2 https://cloudflare.com/ 2>&1 | grep -i "alt-svc"
```

---

## 4. Browser Security Model

### Same-Origin Policy (SOP)
Two URLs share an origin only when **scheme + hostname + port** all match exactly. Cross-origin reads of DOM and response bodies are blocked by the browser.

| URL A | URL B | Same origin? |
| :--- | :--- | :--- |
| `https://app.example.com` | `https://app.example.com/api` | Yes |
| `https://app.example.com` | `http://app.example.com` | **No** — different scheme |
| `https://app.example.com` | `https://api.example.com` | **No** — different hostname |
| `https://app.example.com:443` | `https://app.example.com:8443` | **No** — different port |

### Cross-Origin Resource Sharing (CORS)
CORS relaxes SOP for explicitly allowed cross-origin HTTP requests.

**Preflight flow** (for non-simple requests: `DELETE`, `PUT`, custom headers, `Content-Type: application/json`):
```
Browser → OPTIONS /api/data HTTP/1.1
          Origin: https://frontend.example.com
          Access-Control-Request-Method: DELETE
          Access-Control-Request-Headers: Authorization

Server  ← 204 No Content
          Access-Control-Allow-Origin: https://frontend.example.com
          Access-Control-Allow-Methods: GET, DELETE
          Access-Control-Allow-Headers: Authorization
          Access-Control-Max-Age: 600
```

**Security rules:**

| Rule | Rationale |
| :--- | :--- |
| Never use `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` | Browsers refuse this combination, but misconfigurations in frameworks silently set both |
| Maintain an explicit origin allowlist; do not reflect the `Origin` header verbatim | Reflected-origin CORS allows any attacker origin to make credentialed requests |
| Set `Access-Control-Max-Age` to ≤ 600 s | Prevents stale preflight caches masking permission changes |

```bash
# Test CORS response headers
curl -sv -X OPTIONS https://api.example.com/users \
  -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: GET" 2>&1 | grep -i "access-control"
```

### Content Security Policy (CSP) Level 3

CSP instructs the browser which sources are trusted for each resource type, blocking XSS payloads that cannot load from an approved source.

**Key directives:**

| Directive | Controls |
| :--- | :--- |
| `default-src 'self'` | Fallback for all resource types |
| `script-src 'nonce-<base64>' 'strict-dynamic'` | Scripts with a per-request nonce; `strict-dynamic` propagates trust to scripts loaded by trusted scripts |
| `object-src 'none'` | Block Flash, ActiveX (attack surface) |
| `base-uri 'self'` | Prevent `<base>` tag hijacking |
| `frame-ancestors 'none'` | Equivalent to `X-Frame-Options: DENY` but more granular |
| `upgrade-insecure-requests` | Auto-upgrade HTTP sub-resources to HTTPS |
| `report-uri /csp-report` (deprecated) / `report-to` | Violation telemetry |

**Nonce-based CSP (recommended over hash for dynamic pages):**
```http
Content-Security-Policy: default-src 'self';
  script-src 'nonce-r4nd0mB4se64==' 'strict-dynamic';
  style-src 'nonce-r4nd0mB4se64==';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
  report-to csp-endpoint
```
```html
<script nonce="r4nd0mB4se64==">/* inline script */</script>
```

**Hash-based CSP (for static pages):**
```http
Content-Security-Policy: script-src 'sha256-<hash_of_script_content>'
```

### HTTP Strict Transport Security (HSTS)
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
- `max-age` — seconds the browser enforces HTTPS-only. Start at 300 s, ramp to 31 536 000 (1 year) after testing.
- `includeSubDomains` — applies to all subdomains; ensure `*.example.com` has valid TLS before enabling.
- `preload` — submits the domain to the browser HSTS preload list (hstspreload.org). This is a **one-way door**; removal takes months.

```bash
# Verify HSTS header
curl -sv https://example.com/ 2>&1 | grep -i "strict-transport"
```

### Subresource Integrity (SRI)
Browsers verify a SHA-256/384/512 digest of every external script or stylesheet before executing it. Blocks CDN compromise or hijack attacks.

```html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-<base64_hash>"
        crossorigin="anonymous"></script>
```

Generate the hash:
```bash
curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
```

### Permissions-Policy (formerly Feature-Policy)
Restricts which browser APIs a page and its iframes may use:
```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```
This prevents a compromised third-party iframe from silently activating the camera or reading the user's location.

---

## 5. API Paradigms & Attack Surfaces

### GraphQL
GraphQL exposes a single endpoint (`/graphql`) that accepts arbitrary queries.

**High-risk attack surfaces:**

| Vector | Description | Mitigation |
| :--- | :--- | :--- |
| **Introspection** | `{ __schema { types { name fields { name } } } }` dumps the entire API schema | Disable introspection in production: `introspection: false` |
| **Query depth** | Deeply nested queries trigger O(n²) DB joins | `max_depth: 10` |
| **Query complexity** | `aliases` allow executing the same resolver hundreds of times in one request | Complexity scoring (reject > 1000) |
| **Batching attacks** | `[{ query: "mutation login..." }, ...]` — fire 500 login attempts in one HTTP request | Disable batching or rate-limit at mutation level |
| **IDOR via node IDs** | Opaque base64 IDs (`type:id`) are not access-controlled by default | Per-field resolver authorization checks |

```bash
# Probe introspection status
curl -s -X POST https://api.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}}}"}' | jq .data
```

### gRPC
gRPC encodes messages in Protocol Buffers (protobuf) over HTTP/2. The binary framing and compact encoding makes gRPC traffic opaque to generic WAFs and proxies.

**Attack surface:**

| Vector | Mitigation |
| :--- | :--- |
| Missing `deadline` / `timeout` in client calls | Set per-call deadlines; enforce server-side max deadline |
| Server reflection enabled | Disable `grpc.reflection.v1alpha.ServerReflection` in production |
| mTLS not enforced | Require mutual TLS on all gRPC channels; reject calls without client cert |
| Protobuf-deserialization of unknown fields | Validate field presence and types in handler; treat unexpected fields as errors |

### WebSockets
WebSocket upgrades an HTTP connection to a bidirectional, persistent channel.

**Handshake:**
```text
GET /ws HTTP/1.1
Host: app.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://app.example.com

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**Security rules:**

| Rule | Detail |
| :--- | :--- |
| Validate `Origin` header on upgrade | The browser sends `Origin`; the server must reject upgrades from unexpected origins (SOP does not apply to WebSocket upgrades) |
| Authenticate before upgrade | Check session/JWT before issuing `101`; the connection is persistent so there is no per-message auth opportunity |
| Apply message-level rate limiting | One TCP connection can send unlimited frames; treat incoming messages as untrusted input |
| Enable per-message deflate (`permessage-deflate`) with caution | CRIME/BREACH-class compression oracle attacks apply to compressed WebSocket streams carrying sensitive data |

```bash
# Test WebSocket upgrade (requires websocat)
websocat -v wss://app.example.com/ws --header "Origin: https://app.example.com"
```

---

## Operational Gotchas

- **HTTP/2 and NGINX upstream** — by default, NGINX proxies HTTP/1.1 to upstream even when the client connects over HTTP/2. Enable `grpc_pass` or `proxy_http_version 2.0` (NGINX Plus) to use HTTP/2 upstream.
- **CORS and cookies** — `SameSite=Strict` blocks cross-site cookie delivery even with correct CORS headers; use `SameSite=Lax` for APIs that need cookies cross-origin.
- **CSP and inline event handlers** — `onclick="..."` attributes break under `script-src 'nonce-...'` even with `'strict-dynamic'`; refactor to `addEventListener`.
- **0-RTT and state-mutating endpoints** — CDNs (Cloudflare, Fastly) can replay 0-RTT data; never process POST/PATCH/DELETE in a 0-RTT handler.
- **HSTS on non-default ports** — `includeSubDomains` with a subdomain on port 8443 that lacks TLS will make that subdomain unreachable for the `max-age` duration.

---

## Related

- [HTTP Security Headers](http-security-headers.md)
- [Session Management](session-management.md)
- [TLS/SSL Fundamentals](../../fundamentals/networking/tls-ssl.md)
- [WAF Fundamentals & Tuning](../../tasks/hardening/waf-fundamentals-and-tuning.md)
- [CSRF Defense](csrf-defense.md)
- [SSRF Defense](ssrf-defense.md)
- [REST Architecture](../../fundamentals/apis/rest-architecture.md)
- [Web Application Assessment (Offensive)](../../offensive/web-application-assessment.md)
- [Web Attack Detection — SPL](../../detection/spl/web-attacks.md)
- [Web Attack Detection — KQL](../../detection/kql/web-attacks.md)

## External Resources & White Papers

- [RFC 9114 — HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9000 — QUIC Transport Protocol](https://www.rfc-editor.org/rfc/rfc9000)
- [WHATWG Fetch Standard — CORS](https://fetch.spec.whatwg.org/)
- [CSP Level 3 — W3C](https://www.w3.org/TR/CSP3/)
- [HSTS Preload List](https://hstspreload.org)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
