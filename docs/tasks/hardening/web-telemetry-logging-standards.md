---
title: Web Telemetry, Logging & Auditing Standards
type: entry
platforms: [Linux, Windows, AWS, Azure]
languages: [Bash, PowerShell]
tasks: [Hardening, Assurance, Detection Engineering, Governance]
category: Web Application Security
security_domain: Operations
author: RJGProjectz
date_created: 2026-10-28
last_updated: 2026-10-28
tags: [logging, telemetry, log-pipeline, filebeat, fluentd, vector, ecs, ocsf, siem, log-schema, pii-redaction, pci-dss, log-integrity, web-server-logs, structured-logging]
aliases: [web server access logs, structured log format, log ingestion pipeline, ECS schema, OCSF, Filebeat configuration, Fluentd pipeline, log PII redaction, PCI log requirements, log tamper resistance, centralized logging, trace ID correlation, X-Request-ID]
difficulty: intermediate
verified: true
last_verified: 2026-10-28
---

# Web Telemetry, Logging & Auditing Standards
> **Created**: 2026-10-28T00:00:00Z
> **Last Modified**: 2026-10-28T00:00:00Z
> **Author**: RJGProjectz

Definitive reference for web-tier logging: what to capture at each ingestion point, the mandatory field schema, log pipeline patterns (Filebeat → Kafka → SIEM), compliance requirements for PII/PCI redaction, and log integrity controls.

---

## 1. Ingestion Points

A complete web telemetry strategy captures logs from all four tiers:

| Source | Log Types | Default Locations |
| :--- | :--- | :--- |
| **Web server (NGINX)** | Access log (every request), error log (4xx/5xx, upstream errors, start/stop) | `/var/log/nginx/access.log`, `/var/log/nginx/error.log` |
| **Web server (Apache)** | Access log, error log, mod_security/WAF log | `/var/log/apache2/access.log`, `/var/log/apache2/error.log` |
| **WAF** | Block/pass events with matched rule ID, anomaly score, payload excerpt | Application-specific; ModSecurity → `/var/log/modsec_audit.log` |
| **Application** | Structured JSON application events (auth, business events, errors) | Stdout/stderr (containerised) or `/var/log/app/app.log` |
| **OS / host** | Auth events (sshd, PAM), sudo, cron, kernel | `/var/log/auth.log`, `/var/log/syslog`, Windows Security Event Log |

---

## 2. Standardised Log Schema

### Required fields (web access log minimum)

Every HTTP access log line must carry:

| Field (ECS name) | NGINX variable | Purpose |
| :--- | :--- | :--- |
| `client.ip` | `$realip_remote_addr` | True client IP (after CDN/proxy trust) |
| `http.request.headers.x-forwarded-for` | `$http_x_forwarded_for` | Full XFF chain for audit trail |
| `user_agent.original` | `$http_user_agent` | Threat intel, fingerprinting |
| `url.full` | `$request` | Full request line including method, URI, protocol |
| `http.response.status_code` | `$status` | Response classification |
| `http.response.bytes` | `$body_bytes_sent` | Data transfer audit |
| `event.duration` | `$request_time` | Latency; anomaly detection |
| `trace.id` / `x_request_id` | `$request_id` | End-to-end request correlation |
| `http.request.referrer` | `$http_referer` | Referrer chain; exfiltration detection |
| `user.name` | (application-injected) | Authenticated user; inject via upstream header |
| `tls.version` | `$ssl_protocol` | TLS version enforcement audit |
| `tls.cipher` | `$ssl_cipher` | Cipher audit |

### NGINX JSON access log format

```nginx
http {
    log_format json_combined escape=json
        '{'
            '"timestamp":"$time_iso8601",'
            '"client_ip":"$realip_remote_addr",'
            '"xff":"$http_x_forwarded_for",'
            '"method":"$request_method",'
            '"uri":"$uri",'
            '"query":"$query_string",'
            '"protocol":"$server_protocol",'
            '"status":$status,'
            '"bytes_sent":$body_bytes_sent,'
            '"request_time":$request_time,'
            '"upstream_response_time":"$upstream_response_time",'
            '"request_id":"$request_id",'
            '"user_agent":"$http_user_agent",'
            '"referer":"$http_referer",'
            '"tls_protocol":"$ssl_protocol",'
            '"tls_cipher":"$ssl_cipher"'
        '}';

    access_log /var/log/nginx/access.log json_combined;
}
```

### Application structured log fields

Applications should emit JSON lines with these additional fields:

```json
{
  "timestamp": "2026-10-28T14:32:01.123Z",
  "level": "INFO",
  "trace_id": "a1b2c3d4e5f6",
  "span_id": "aabbccdd",
  "service.name": "user-api",
  "service.version": "2.4.1",
  "http.request.id": "req-a1b2c3",
  "user.id": "usr_12345",
  "user.name": "alice@example.com",
  "event.action": "user.login",
  "event.outcome": "success",
  "source.ip": "198.51.100.10",
  "message": "User authenticated successfully"
}
```

**Never log in application events:**
- Passwords or secrets (even hashed)
- Full credit card numbers / PANs (PCI DSS requirement 10.3.3)
- Social Security Numbers or government ID numbers
- Full session tokens or JWTs (log token ID/jti only)

---

## 3. Log Pipeline Architectures

### Filebeat → Elasticsearch (ELK) pipeline

```yaml
# /etc/filebeat/filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/nginx/access.log
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      log_source: nginx-access
      environment: production
    fields_under_root: true

  - type: log
    enabled: true
    paths:
      - /var/log/nginx/error.log
    fields:
      log_source: nginx-error
      environment: production
    fields_under_root: true

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
  - drop_fields:
      fields: ["log.file.path"]    # Reduce noise

output.kafka:
  hosts: ["kafka-broker:9092"]
  topic: "web-logs-production"
  codec.json:
    pretty: false
  required_acks: 1
  max_message_bytes: 1000000
```

### Vector (Datadog Observability Pipelines / self-hosted)

Vector uses a composable pipeline: `sources → transforms → sinks`.

```toml
# /etc/vector/vector.toml
[sources.nginx_access]
type = "file"
include = ["/var/log/nginx/access.log"]

[transforms.parse_json]
type = "remap"
inputs = ["nginx_access"]
source = '''
  . = parse_json!(.message)
  .event.dataset = "nginx.access"
  # Redact query string parameters that may contain PII
  .query = redact(.query, filters: [r'\bpassword=[^&]*', r'\btoken=[^&]*', r'\bsession=[^&]*'])
'''

[sinks.elasticsearch]
type = "elasticsearch"
inputs = ["parse_json"]
endpoint = "https://es-cluster:9200"
index = "web-logs-%Y.%m.%d"
bulk.action = "index"
```

### Kafka as a buffer/queue

For high-volume web tiers, ship logs to Kafka first. This decouples shipper throughput from SIEM ingestion speed and survives SIEM downtime:

```
NGINX log → Filebeat → Kafka topic (replicated, 7-day retention) → Logstash/Kafka consumer → SIEM
```

Key Kafka settings for log topics:
- `retention.ms = 604800000` (7 days)
- `min.insync.replicas = 2` (durability guarantee)
- `compression.type = snappy` (CPU-efficient compression)

---

## 4. SIEM Parsing & Index Retention

### ECS (Elastic Common Schema) field mapping

Map your JSON log fields to ECS to make cross-source queries consistent:

| Your field | ECS field |
| :--- | :--- |
| `client_ip` | `source.ip` |
| `status` | `http.response.status_code` |
| `request_time` | `event.duration` (convert to nanoseconds: × 1 000 000 000) |
| `user_agent` | `user_agent.original` |
| `uri` | `url.path` |
| `query` | `url.query` |

### OCSF (Open Cybersecurity Schema Framework)

OCSF (v1.x) is gaining traction across cloud SIEMs (AWS Security Lake, Microsoft Sentinel). Web access logs map to OCSF class **Web Resource Access Activity** (class_uid 6003):

```json
{
  "class_uid": 6003,
  "class_name": "Web Resource Access Activity",
  "time": 1761696000000,
  "activity_id": 1,
  "actor": { "user": { "name": "alice@example.com" }, "session": { "uid": "sess_abc" } },
  "http_request": { "method": "GET", "url": { "hostname": "app.example.com", "path": "/api/data" } },
  "http_response": { "code": 200, "latency": 42 },
  "src_endpoint": { "ip": "198.51.100.10" },
  "tls": { "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384" }
}
```

### Retention tiers

| Tier | Duration | Storage | Use |
| :--- | :--- | :--- | :--- |
| **Hot** | 7–30 days | SSD-backed Elasticsearch / Sentinel hot tier | Active querying, real-time detection |
| **Warm** | 31–90 days | HDD-backed / Sentinel warm tier | Incident investigation |
| **Cold** | 91–365 days | Object store (S3/ADLS/GCS) | Compliance, on-demand query |
| **Archive** | 1–7 years | Glacier/Archive tier | Regulatory hold (PCI DSS ≥ 12 months, HIPAA ≥ 6 years) |

---

## 5. PII Redaction & Compliance

### PCI DSS log requirements

PCI DSS v4.0 Requirement 10:
- Log all access to cardholder data (10.2.1).
- Log all actions by users with root/admin access (10.2.1.1).
- Retain logs for 12 months; 3 months immediately available (10.5.1).
- Review logs daily (automated alerting satisfies this) (10.4.1).
- **PAN must never appear in logs** (Requirement 3.4); use truncation or tokenisation at application layer.

### GDPR / privacy redaction

```python
# Python example: redact PII from query strings before logging
import re

def redact_query(query: str) -> str:
    """Remove values for known PII parameters."""
    patterns = [
        r'(?i)(password|passwd|secret|token|api_key|apikey|access_token|credit_card)=[^&]*',
        r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # card number pattern
        r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
    ]
    for pattern in patterns:
        query = re.sub(pattern, r'\1=REDACTED', query)
    return query
```

IP anonymisation (GDPR Article 4 — IP addresses are PII in EU):
```nginx
# Truncate the last octet of IPv4 before logging
map $remote_addr $ip_anon {
    ~(?P<ip>\d+\.\d+\.\d+\.)  "${ip}0";
    default                     $remote_addr;
}
log_format anonymised_access '$ip_anon - $remote_user [$time_local] ...';
```

---

## 6. Log Integrity & Tamper Resistance

### Immutable log storage

| Platform | Method |
| :--- | :--- |
| **Linux** | `chattr +a /var/log/nginx/access.log` — append-only bit; removes file deletion/truncation even as root (requires `CAP_LINUX_IMMUTABLE` to set/unset) |
| **AWS CloudWatch** | Enable CloudWatch Log Groups with `Retention` + S3 export with Object Lock (WORM) |
| **Azure Monitor** | DCR immutable workspace: `az monitor log-analytics workspace update --set properties.immutabilityEnabled=true` |
| **Splunk** | `index = web_logs [frozen|cold]` with Splunk SmartStore and S3 Object Lock for frozen data |

### Forward integrity (hash chaining)

For compliance requiring tamper evidence, implement log signing. A simple approach using `sha256sum` per log rotation:

```bash
# Rotate with integrity hash
/usr/sbin/logrotate /etc/logrotate.d/nginx
# After rotate, hash the archived file
sha256sum /var/log/nginx/access.log.1 >> /var/log/nginx/access.log.sha256.manifest
# Sign the manifest with the server's private key (OpenSSL)
openssl dgst -sha256 -sign /etc/ssl/private/log-signing.key \
    -out /var/log/nginx/access.log.1.sig \
    /var/log/nginx/access.log.1
```

Verify at audit time:
```bash
openssl dgst -sha256 -verify /etc/ssl/certs/log-signing.pub \
    -signature /var/log/nginx/access.log.1.sig \
    /var/log/nginx/access.log.1
```

---

## 7. Operational Gotchas

- **`$request_time` includes upstream time** — use `$upstream_response_time` separately to distinguish proxy latency from upstream latency.
- **JSON escaping in NGINX log format** — the `escape=json` directive (NGINX ≥ 1.11.8) handles special characters in `$http_user_agent` and `$uri`; without it, unescaped quotes break JSON parsers.
- **Log rotation and Filebeat** — Filebeat tracks file inodes, not paths. After logrotate, Filebeat detects the new file automatically, but `copytruncate` (replaces content in-place) causes Filebeat to miss the rotated lines. Use `create` mode (default) with `postrotate: nginx -s reopen`.
- **Kafka producer `acks=0`** — fire-and-forget delivery; messages can be lost on broker restart. Use `acks=1` minimum for log pipelines; `acks=-1` (all in-sync replicas) for compliance-sensitive streams.
- **High-cardinality trace IDs in SIEM** — `$request_id` (NGINX) generates a random 32-character hex string per request. Ensure the SIEM index is configured as a `keyword` type (not `text`) to avoid tokenisation overhead.

---

## Related

- [Centralised Log Forwarding (WEF + rsyslog)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md)
- [NGINX Web Server Hardening](nginx-web-server-hardening.md)
- [WAF Fundamentals & Tuning](waf-fundamentals-and-tuning.md)
- [SIEM Concept](../../fundamentals/concepts/siem.md)
- [Web Attack Detection — SPL](../../detection/spl/web-attacks.md)
- [Web Attack Detection — KQL](../../detection/kql/web-attacks.md)
- [Detection-as-Code Pipeline](../../tasks/detection-engineering/detection-as-code-pipeline.md)

## External Resources & White Papers

- [Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [OCSF Schema Browser](https://schema.ocsf.io/)
- [PCI DSS v4.0 — Requirement 10](https://www.pcisecuritystandards.org/document_library/)
- [Filebeat Reference Guide](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Vector Documentation](https://vector.dev/docs/)
