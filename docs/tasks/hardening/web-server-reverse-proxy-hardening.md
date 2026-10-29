---
title: Web Server & Reverse Proxy Hardening
type: entry
platforms: [Linux]
languages: [Bash]
tasks: [Hardening, Assurance, Assessment]
category: Web Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [nginx, apache, caddy, envoy, reverse-proxy, load-balancer, mtls, tls-termination, rate-limiting, x-forwarded-for, upstream-proxy, web-server-hardening]
aliases: [NGINX hardening, Apache hardening, reverse proxy security, X-Forwarded-For spoofing, mTLS termination, upstream load balancing, web server configuration, rate limiting nginx]
difficulty: intermediate
verified: true
last_verified: 2026-10-28
---

# Web Server & Reverse Proxy Hardening
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Configuration changes to a production web server can cause an outage or expose sensitive data.
> 1. Test all changes in a staging environment first.
> 2. Use `nginx -t` / `apachectl configtest` before reloading.
> 3. Roll back with `nginx -s reload` of the previous config on failure.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Cipher suite and TLS settings are version-sensitive. Confirm against the vendor docs for your installed version before deploying.

Reference covering architectural differences between major web servers and reverse proxies, production hardening for NGINX, and deep-dive reverse-proxy patterns including mTLS termination, rate limiting, and upstream spoofing defense.

---

## 1. Architecture Comparison

Understanding concurrency models helps diagnose performance and configure resource limits correctly.

| Server / Proxy | Concurrency Model | Key Characteristics |
| :--- | :--- | :--- |
| **NGINX** | Event-driven, non-blocking I/O (epoll/kqueue). One worker process per CPU core, each handling thousands of concurrent connections via an event loop. | Low memory per connection (~1–2 KB idle). Excellent for static files and reverse proxy. Limited dynamic content generation (requires FastCGI/uWSGI). |
| **Apache HTTPD (MPM prefork)** | One process per connection. Each child is isolated (mod_php safe). | High memory at scale (~10 MB/process). Simple but does not scale beyond ~1 000 concurrent connections on commodity hardware. |
| **Apache HTTPD (MPM event)** | Thread pool with keep-alive connections handled by a dedicated listener thread. Worker threads freed for active I/O only. | Closer to NGINX performance. Recommended for HTTP/2. |
| **Caddy** | Event-driven (Go runtime goroutines). Automatic HTTPS via ACME (Let's Encrypt / ZeroSSL) built in. | Zero-config TLS renewal. JSON or Caddyfile configuration. Smaller community footprint than NGINX/Apache. |
| **Envoy** | Event-driven (libevent). Acts as a data-plane proxy; configured dynamically via xDS APIs (Istio control plane). | Designed for service-mesh. Supports gRPC-native proxying, circuit breakers, distributed tracing. Steeper ops overhead for standalone deployments. |

---

## 2. NGINX — Information Disclosure Prevention

Strip version banners and server identity from all responses.

```nginx
# /etc/nginx/nginx.conf
http {
    server_tokens     off;          # Removes version from Server: header and error pages
    more_clear_headers 'Server';    # Requires headers-more-nginx-module; removes Server entirely
    more_clear_headers 'X-Powered-By';

    # Error pages — serve generic HTML, no stack traces
    error_page 400 401 403 404 /errors/4xx.html;
    error_page 500 502 503 504 /errors/5xx.html;
}
```

**Verify:**
```bash
curl -sv https://example.com/ 2>&1 | grep -i "^< server:"
# Expected: empty or "Server: " with no version string
```

---

## 3. TLS Termination & Cipher Suite Hardening

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.crt;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # TLS versions — disable TLS 1.0 and 1.1
    ssl_protocols TLSv1.2 TLSv1.3;

    # Cipher suites — prefer forward-secrecy suites; disable 3DES, RC4, export
    ssl_ciphers 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5';
    ssl_prefer_server_ciphers on;

    # Session resumption (reduces handshake overhead)
    ssl_session_timeout  1d;
    ssl_session_cache    shared:SSL:10m;
    ssl_session_tickets  off;     # Disable session tickets to avoid PFS regression with long-lived TLS secrets

    # OCSP stapling — reduces client latency for certificate validation
    ssl_stapling          on;
    ssl_stapling_verify   on;
    resolver              8.8.8.8 1.1.1.1 valid=300s;
    resolver_timeout      5s;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
```

**Audit cipher configuration:**
```bash
openssl s_client -connect example.com:443 -brief 2>&1 | grep -E "(Protocol|Cipher)"
# Or use testssl.sh for a comprehensive scan
curl -s https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/testssl.sh | bash -s -- --fast example.com
```

---

## 4. Mutual TLS (mTLS) Termination

For service-to-service or high-assurance API clients, require the client to present a certificate signed by your internal CA.

```nginx
server {
    listen 443 ssl http2;

    ssl_certificate     /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # mTLS — require client certificate
    ssl_client_certificate /etc/ssl/certs/internal-ca.crt;
    ssl_verify_client      on;
    ssl_verify_depth       2;     # Depth for intermediate CA chains

    location /api/ {
        # Forward client cert identity to upstream app
        proxy_set_header X-Client-Cert         $ssl_client_escaped_cert;
        proxy_set_header X-Client-Cert-DN      $ssl_client_s_dn;
        proxy_set_header X-Client-Verify       $ssl_client_verify;
        proxy_pass http://backend_api;
    }
}
```

**Operational gotcha:** `ssl_client_certificate` must contain the full CA chain (root + intermediates) in a single PEM file, not just the root. Missing intermediates cause `SSL_CTX_load_verify_locations` errors at startup.

**Test with a valid client cert:**
```bash
curl -sv --cert client.crt --key client.key --cacert ca.crt https://example.com/api/
```

**Test rejection of missing/invalid cert:**
```bash
curl -sv --cacert ca.crt https://example.com/api/  # No client cert — expect 400
```

---

## 5. Resource Limiting & DoS Mitigation

### Connection throttling

```nginx
http {
    # Define a shared zone: 10 MB stores ~160 000 IP entries
    limit_conn_zone $binary_remote_addr zone=per_ip:10m;

    server {
        limit_conn per_ip 20;               # Max 20 concurrent connections per client IP
        limit_conn_status 429;
        limit_conn_log_level warn;
    }
}
```

### Rate limiting

```nginx
http {
    # 10 requests/second per IP, bursting to 20 without delay
    limit_req_zone $binary_remote_addr zone=api_ratelimit:10m rate=10r/s;

    server {
        location /api/ {
            limit_req zone=api_ratelimit burst=20 nodelay;
            limit_req_status 429;
            limit_req_log_level warn;
        }
    }
}
```

**Gotcha:** `nodelay` allows burst requests to be served immediately rather than queued; without it, burst requests queue and add latency. Use `delay=5` instead of `nodelay` if you want to queue but not drop burst traffic.

### Payload size restrictions

```nginx
http {
    client_max_body_size     10m;   # Reject bodies > 10 MB (413 error)
    client_body_buffer_size  128k;  # Buffer size before spilling to disk
    client_header_buffer_size 1k;   # Normal single-line header
    large_client_header_buffers 4 8k; # Max header size = 4 × 8 KB = 32 KB

    # Timeouts — prevent Slowloris-style resource exhaustion
    client_body_timeout   12s;
    client_header_timeout 12s;
    keepalive_timeout     15s 15s;  # Server timeout; timeout sent in Keep-Alive header
    send_timeout          10s;
}
```

**Detect buffer overflow / slow-client attacks in logs:**
```bash
grep " 408 \| 413 \| 414 " /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

---

## 6. Upstream Proxying & Load Balancing

### Load-balancing algorithms

```nginx
upstream backend_api {
    # Round-robin (default): requests distributed sequentially
    server 10.0.0.10:8080;
    server 10.0.0.11:8080;

    # least_conn: route to server with fewest active connections
    # least_conn;

    # ip_hash: sticky sessions based on client IP (modulo 256)
    # ip_hash;

    # Random with two: pick the better of two random servers (requires NGINX Plus or Tengine)
    # random two least_conn;

    keepalive 32;   # Persistent upstream connections (reuse for HTTP/1.1 keep-alive)
}
```

### Health checks (NGINX open source)

```nginx
upstream backend_api {
    server 10.0.0.10:8080;
    server 10.0.0.11:8080 backup;

    # Passive health check: mark server down after 3 consecutive failures within 30 s
    server 10.0.0.10:8080 max_fails=3 fail_timeout=30s;
}
```

### WebSocket proxying

```nginx
location /ws/ {
    proxy_pass http://websocket_upstream;
    proxy_http_version 1.1;
    proxy_set_header Upgrade    $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 3600s;   # WebSocket connections are long-lived; prevent timeout
    proxy_send_timeout 3600s;
}
```

---

## 7. X-Forwarded-* Headers — Defense Against Spoofing

When NGINX sits behind a CDN or upstream proxy, it must:
1. Trust `X-Forwarded-For` only from known upstream IPs.
2. Append its own IP (or the real client IP) to the header.
3. Never blindly pass attacker-controlled `X-Forwarded-For` values to the application.

### Real IP extraction from trusted upstream

```nginx
http {
    # Declare the upstream proxy / CDN IP ranges that you trust
    set_real_ip_from  10.0.0.0/8;
    set_real_ip_from  192.168.0.0/16;
    set_real_ip_from  172.16.0.0/12;
    # For Cloudflare: add their published IP ranges
    # https://www.cloudflare.com/ips/

    real_ip_header    X-Forwarded-For;  # Or CF-Connecting-IP for Cloudflare
    real_ip_recursive on;               # Walk the XFF chain, discarding known proxy IPs
}
```

### Defensive header rewrite (prevent upstream spoofing)

```nginx
location /api/ {
    # Remove client-supplied headers before forwarding
    proxy_set_header X-Forwarded-For   $realip_remote_addr;
    proxy_set_header X-Real-IP         $realip_remote_addr;
    # Do NOT use $http_x_forwarded_for — attacker can pre-inject values

    proxy_set_header Host              $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Request-ID      $request_id;   # Correlation / tracing

    proxy_pass http://backend_api;
}
```

**Attack scenario if not hardened:**
An attacker sends `X-Forwarded-For: 127.0.0.1` to an application that trusts XFF for IP-based allow-listing. Without the `real_ip_*` module enforcing trust, `$http_x_forwarded_for` = `127.0.0.1` and the application grants localhost access.

---

## 8. Default Deny, Directory Hardening & Information Disclosure

```nginx
server {
    root /var/www/html;

    # Deny access to hidden files (.git, .env, .htaccess)
    location ~ /\.(?!well-known\/) {
        deny all;
        return 404;
    }

    # Deny access to backup files and source control
    location ~* \.(git|svn|bak|swp|old|orig)$ {
        deny all;
        return 404;
    }

    # Disable directory listings
    autoindex off;

    # Restrict methods to GET, HEAD, POST only
    if ($request_method !~ ^(GET|HEAD|POST)$) {
        return 405;
    }
}
```

---

## 9. Troubleshooting Scenarios

| Symptom | Likely Cause | Diagnosis |
| :--- | :--- | :--- |
| `502 Bad Gateway` | Upstream not listening / wrong port | `curl http://127.0.0.1:8080/` directly on the server; check `upstream` block IPs |
| `504 Gateway Timeout` | Upstream takes too long; `proxy_read_timeout` too short | Increase `proxy_read_timeout`; check upstream app logs |
| `413 Request Entity Too Large` | `client_max_body_size` too small for file uploads | Increase to match expected payload |
| mTLS: `400 No required SSL certificate was sent` | Client did not present a certificate | Check client `-cert`/`-key` flags; verify CA chain in `ssl_client_certificate` |
| `real_ip` shows wrong IP | `set_real_ip_from` missing the actual upstream proxy IP | `$remote_addr` shows the direct connector; add that IP to `set_real_ip_from` |
| Rate limit applied to all users | Using `$remote_addr` behind a CDN — all traffic appears as CDN IP | Switch zone key to `$realip_remote_addr` after configuring `set_real_ip_from` |

---

## Related

- [Apache & PHP Web Server Hardening](apache-php-web-server-hardening.md)
- [NGINX Web Server Hardening](nginx-web-server-hardening.md)
- [WAF Fundamentals & Tuning](waf-fundamentals-and-tuning.md)
- [HTTP Protocol Mechanics & Browser Security Model](../../fundamentals/web-apps/http-protocol-mechanics.md)
- [TLS/SSL Fundamentals](../../fundamentals/networking/tls-ssl.md)
- [Web Telemetry, Logging & Auditing Standards](web-telemetry-logging-standards.md)
- [Web Attack Detection — SPL](../../detection/spl/web-attacks.md)

## External Resources & White Papers

- [NGINX Security Controls](https://docs.nginx.com/nginx/admin-guide/security-controls/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [testssl.sh — TLS/SSL Scanner](https://testssl.sh/)
