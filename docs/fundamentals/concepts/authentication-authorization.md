---
title: Authentication and Authorization in Web Applications
type: concept
platforms: [Linux, Windows]
languages: [HTTP, REST API, Python]
tasks: [Assurance, Investigation, Hardening]
category: Application Security
security_domain: Application
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [concept, authentication, authorization, oauth, jwt, broken-auth, session-management, owasp]
aliases: [broken authentication, broken access control, OAuth 2.0, JWT security, session token security, OWASP A01 A07]
difficulty: intermediate
verified: false
---

# Authentication and Authorization in Web Applications
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** authentication asks "who are you?" and authorization asks "what can you do?" — web applications that confuse or misimplement either are routinely compromised.

## What it is

**Authentication** is the mechanism by which an application confirms a caller's identity. **Authorization** is the separate step that determines what that identity is permitted to do. The two are often conflated in code — a bug in either leads to a different class of vulnerability, and defenders need to recognise both.

Modern web applications rarely implement authentication from scratch. Instead they delegate to:

- **Session tokens** — a random opaque value stored server-side; included in every request as a cookie. The server looks up the session to determine the authenticated user.
- **JSON Web Tokens (JWT)** — a self-contained signed (or encrypted) token the client holds. The server validates the signature and reads claims directly, without a database lookup.
- **OAuth 2.0 / OpenID Connect (OIDC)** — a delegation framework. The resource server trusts an authorization server (identity provider) to issue access tokens scoped to specific resources.

**OWASP Top 10 context:**
- **A01:2021 Broken Access Control** — authorization logic fails; a user reaches resources or actions they should not.
- **A07:2021 Identification and Authentication Failures** — session fixation, weak tokens, missing re-authentication, credential stuffing exposure.

## How it works

```text
Client                     Application                 Identity Provider
  │                             │                              │
  │── POST /login ─────────────►│                              │
  │   (username + password)     │── validate, issue token ────►│ (optional: OIDC/OAuth)
  │◄── Set-Cookie: session=xyz ─│◄── token issued ─────────────│
  │                             │
  │── GET /account ────────────►│
  │   Cookie: session=xyz       │ look up session → user "alice"
  │                             │ check: is alice allowed to GET /account?
  │◄── 200 OK (account data) ───│
```

**Session token weaknesses:**
- Tokens generated from predictable seeds (timestamp, username hash) are guessable.
- Overly long session lifetimes without re-authentication for sensitive actions.
- Tokens transmitted over HTTP (cleartext) or stored in `localStorage` (exposed to XSS).
- Missing `HttpOnly` and `Secure` cookie flags.
- Session fixation: attacker provides a known session ID before authentication, then authenticates as the victim with that ID.

**JWT weaknesses:**
- Accepting the `alg: none` algorithm — bypasses signature verification entirely.
- Symmetric (HS256) secrets shared between token issuer and verifier that are weak or reused.
- Missing expiry (`exp`) claim, or not validating it.
- Sensitive data in the payload — JWT payloads are base64-encoded, not encrypted; anyone can read them.

**OAuth 2.0 weaknesses:**
- Open redirects in the `redirect_uri` parameter allow tokens to be delivered to attacker-controlled pages.
- Accepting authorization codes or tokens from a different `state` value (CSRF on the authorization flow).
- Overly broad scope grants; applications requesting more permissions than they need.

**Broken access control** is the most consistently exploited class. Common patterns:
- Insecure Direct Object References (IDOR): changing a numeric ID in a URL or POST body to access another user's record.
- Privilege escalation: changing a role claim in a JWT or a hidden form field to gain elevated access.
- Missing server-side authorization: front-end hides admin menus, but the API endpoint is unprotected.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1556](https://attack.mitre.org/techniques/T1556/) — Modify Authentication Process · [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts |
| **What it leads to** | account takeover, horizontal escalation to other users' data, vertical escalation to admin functions |
| **Where defenders meet it** | SAST findings, bug bounty reports, application security reviews, access-control regression tests |

## Do it

Test for missing authorization on a web application endpoint you own:

```bash
# Verify that unauthenticated requests are rejected
curl -sv https://app.example.internal/api/v1/admin/users \
  -H "Accept: application/json"
# Expect: 401 Unauthorized or 403 Forbidden — not 200

# Test that a low-privileged token cannot reach a privileged endpoint
TOKEN="<low-privilege-jwt>"
curl -sv https://app.example.internal/api/v1/admin/users \
  -H "Authorization: Bearer $TOKEN"
# Expect: 403 Forbidden
```

Inspect a JWT payload (no secret needed — payload is only base64):

```bash
# Decode JWT payload (field 2 of three dot-separated parts)
echo "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJ1c2VyIn0.sig" \
  | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

> [!CAUTION]
> **SECURITY WARNING:** Only test against applications and endpoints you own or have written authorization to assess. Unauthorized access to computer systems is illegal.

## See it

| Source | What you see |
| :--- | :--- |
| Application access log | `403` responses from the same user changing only an ID field — IDOR probing |
| Application access log | Requests to admin paths from accounts without the admin role |
| Web Application Firewall | JWT `alg:none` or `alg:HS256` attempts on an RS256-only endpoint |
| SIEM / authentication log | Multiple `401` from a single IP with rotating usernames — credential stuffing |

## Detect it

- Assessment: [Web Application Assessment](../../offensive/web-application-assessment.md)
- Harden: [Secure SDLC and DevSecOps](secure-sdlc-devsecops.md)
- Concept: [Authentication, MFA, SSO and Federation](authentication-mfa-sso.md)
- Concept: [Access Control Models](access-control-models.md)

## Related concepts

- [Authentication, MFA, SSO and Federation](authentication-mfa-sso.md)
- [Access Control Models](access-control-models.md)
- [Secure SDLC and DevSecOps](secure-sdlc-devsecops.md)
- [Penetration Testing](penetration-testing.md)
