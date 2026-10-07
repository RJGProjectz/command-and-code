---
title: "Fundamentals — API Security & Error Handling"
description: "OWASP API Security Top 10 vulnerabilities, sensitive token redaction in automation logs, and RFC 7807 problem details parsing."
platforms: [Linux, Windows]
languages: [REST API, PowerShell, Python]
tasks: [Automation, Administration, Hardening]
type: entry
verified: true
last_verified: 2026-10-06
difficulty: advanced
---

# API Security & Error Handling

Securing automation scripts and SOAR playbooks requires strict defensive hygiene. Poorly engineered API scripts often leak high-privilege bearer tokens into plain-text log files, fail to validate remote certificates, or swallow actionable error bodies, leaving administrators blind to root causes.

This guide outlines essential defenses against the **OWASP API Security Top 10**, production log **token redaction patterns**, and standardized **RFC 7807 Problem Details** error parsing.

---

## OWASP API Security Top 10 Matrix

Understanding common API vulnerability patterns helps engineers secure integration scripts and custom webhook gateways:

| Risk | Name | Practical Threat in Enterprise SecOps | Defense Strategy |
|:---|:---|:---|:---|
| **API1** | **Broken Object Level Authorization (BOLA)** | A script queries `/devices/{id}` and accesses another tenant's or division's machine because authorization only checked identity, not object ownership. | Ensure backend authorization validates object ownership against the caller's tenant boundary. |
| **API2** | **Broken Authentication** | Scripts hardcode long-lived API keys in repository files; or services accept unverified/unsigned JWTs. | Enforce short-lived OAuth tokens, Key Vault credential stores, and strict JWT signature checks. |
| **API3** | **Broken Object Property Authorization** | Mass assignment: A script sends an entire user object during update and inadvertently grants admin privileges. | Strictly whitelist parameters in update schemas (`PATCH`); never pass raw unvalidated dictionaries. |
| **API4** | **Unrestricted Resource Consumption** | Missing rate limits or unconstrained query parameters allow a rogue script to exhaust database memory. | Enforce client-side rate limits, query timeouts, and strict pagination limits. |
| **API5** | **Broken Function Level Authorization (BFLA)** | An operator with Read-Only rights successfully invokes an administrative action (e.g., `POST /devices/{id}/isolate`). | Enforce RBAC/scopes at every function endpoint; check roles on sensitive operations. |
| **API6** | **Unrestricted Business Flow Access** | Automated scripts abuse bulk registration endpoints or ticket creation APIs faster than humans can triage. | Rate limit sensitive actions; implement anti-automation CAPTCHA/proof-of-work or approval gates. |
| **API7** | **Server Side Request Forgery (SSRF)** | An API accepts a webhook callback URL or image link and fetches internal AWS/Azure metadata services (`169.254.169.254`). | Restrict egress URLs; strictly block private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`). |
| **API8** | **Security Misconfiguration** | APIs expose verbose stack traces, allow outdated TLS 1.0/1.1, or leave default admin endpoints active. | Enforce TLS 1.2+; disable verbose stack traces in production; automate configuration auditing. |
| **API9** | **Improper Inventory Management** | Shadow APIs or deprecated `v1` endpoints remain exposed with old vulnerabilities after `v2` is deployed. | Maintain API catalogs, deprecate stale versions, and monitor perimeter endpoints. |
| **API10**| **Unsafe Consumption of APIs** | A script trusts all data returned by a third-party API without sanitization, leading to SQLi or command injection. | Treat third-party API responses as untrusted user input; validate all data types and schemas. |

---

## Log Sanitization & Token Redaction

One of the most frequent security incidents in SecOps automation is accidental credential leakage in CI/CD pipeline outputs, debug logs, and centralized SIEM log collectors.

> [!CAUTION]
> Never log raw HTTP headers without stripping `Authorization`, `X-Api-Key`, or `Cookie`. Never log raw request bodies that contain secrets or credentials.

### Common Secret Patterns to Sanitize

| Secret Type | Regex Pattern to Match |
|:---|:---|
| **Bearer / JWT Token** | `Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*` |
| **Generic Secret / Password** | `(?i)(client_secret|password|api_key|token)\s*[:=]\s*["']?([^"'\s&]+)` |
| **AWS Access Key** | `AKIA[0-9A-Z]{16}` |

---

## RFC 7807 Problem Details

Modern enterprise APIs (e.g., Microsoft Graph, RFC-compliant microservices) return structured error payloads following **RFC 7807**:

```json
{
  "type": "https://api.contoso.com/errors/quota-exceeded",
  "title": "You have exceeded your monthly quota",
  "status": 403,
  "detail": "Account has processed 10,005 requests out of a 10,000 maximum limit.",
  "instance": "/requests/rq_994821",
  "code": "QuotaExceeded"
}
```

Robust error handlers parse these standardized attributes to produce actionable alerts rather than generic "500 Internal Server Error" failures.

---

## Practical Examples

### 1. PowerShell: Structured RFC 7807 Error Parser & Sanitizer

```powershell
function Invoke-SafeApiCall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ApiAction
    )

    try {
        & $ApiAction
    }
    catch [Microsoft.PowerShell.Commands.HttpResponseException] {
        $response = $_.Response
        $statusCode = [int]$response.StatusCode
        $rawBody = $_.ErrorDetails.Message

        # Sanitize body before logging
        $sanitizedBody = $rawBody -replace 'Bearer\s+[A-Za-z0-9\-_=.]+', 'Bearer [REDACTED]' `
                                  -replace '(?i)(client_secret|password)=([^&]+)', '$1=[REDACTED]'

        # Attempt to parse RFC 7807 Problem Details
        $problemDetails = $null
        try {
            $problemDetails = $sanitizedBody | ConvertFrom-Json
        }
        catch {
            # Not JSON; fall back to raw message
        }

        if ($problemDetails -and $problemDetails.title) {
            Write-Error "API Error [$statusCode]: $($problemDetails.title) - $($problemDetails.detail) [Code: $($problemDetails.code)]"
        }
        else {
            Write-Error "API Error [$statusCode]: $sanitizedBody"
        }
        throw
    }
    catch {
        Write-Error "Fatal transport exception: $_"
        throw
    }
}

# Example Usage:
# Invoke-SafeApiCall {
#     Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/invalid-endpoint" -Headers @{ Authorization = "Bearer secret_jwt" }
# }
```

---

### 2. Python: Logging Filter with Automatic Secret Masking

Implement a custom logging filter in Python to ensure tokens and secrets are redacted from all script output:

```python
import logging
import re

class RedactingFilter(logging.Filter):
    """Filter that masks JWTs, API tokens, and secret parameters from logs."""
    PATTERNS = [
        (re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]+)", re.IGNORECASE), r"Bearer [REDACTED_JWT]"),
        (re.compile(r"(client_secret|password|token|apikey)\s*=\s*['\"]?([^'\"\s&]+)", re.IGNORECASE), r"\1=[REDACTED]"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), r"[REDACTED_AWS_KEY]")
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, repl in self.PATTERNS:
                record.msg = pattern.sub(repl, record.msg)
        return True

# Setup logger with the redacting filter
logger = logging.getLogger("SecurePipeline")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.addFilter(RedactingFilter())
logger.addHandler(handler)

# Test Redaction:
# logger.info("Dispatching request with header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")
# Output: [INFO] Dispatching request with header: Bearer [REDACTED_JWT]
```

---

### 3. Defensive TLS & Certificate Validation

Never disable TLS verification in production scripts (`InvertInvalidCertificate`, `verify=False`, or `curl -k`). Doing so exposes API tokens to adversary-in-the-middle (AiTM) interception.

```python
# CORRECT: Provide internal CA bundle rather than disabling verification
import requests

# If your enterprise uses a private enterprise CA for internal API inspection:
CUSTOM_CA_BUNDLE = "/etc/ssl/certs/enterprise-root-ca.crt"

# Always verify against system or enterprise CA:
response = requests.get(
    "https://internal-soar.corp.local/api/v1/health",
    verify=CUSTOM_CA_BUNDLE,  # NEVER use verify=False in production!
    timeout=10
)
```

---

## Related References

- [REST Architecture & HTTP Semantics](rest-architecture.md) — HTTP verbs, status codes, and idempotency.
- [Authentication & Token Lifecycles](auth-tokens.md) — Managing OAuth 2.0 client credentials and secure storage.
- [Webhooks & Event-Driven Architecture](webhooks-events.md) — HMAC signature validation and replay defense.
- [APIs Catalog](../../apis/index.md) — Standardized API references and enterprise endpoints.
- [Microsoft Graph Conditional Access](../../apis/microsoft-graph/conditional-access.md) — Policy inspection and error handling.
