---
title: Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
tasks:
  - Automation
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - oauth2
  - oidc
  - authentication
  - jwt
---

# Fundamentals — OAuth 2.0 Authorization & OIDC Mechanics

OAuth 2.0 is an authorization framework allowing applications to obtain delegated access, while OpenID Connect (OIDC) is an identity layer providing user authentication.

## 1. Token Types & Lifecycles

| Token | Issued By | Format | Lifetime | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **ID Token** | OIDC | JWT (JSON Web Token) | ~1 hour | Proves user identity to client app |
| **Access Token** | OAuth 2.0 | JWT or Opaque string | 60–90 min | Authorized bearer token passed to APIs (`Authorization: Bearer`) |
| **Refresh Token** | OAuth 2.0 | Cryptographic string | 24h to 90 days | Used to acquire new access tokens without re-authenticating |

---

## 2. Common OAuth 2.0 Grant Types

1. **Authorization Code Flow with PKCE**: Standard for web apps, mobile apps, and single-page apps (SPAs) where a human logs in.
2. **Client Credentials Flow**: Backend daemon/script automation (`client_id` + `client_secret` or certificate). No user interaction.
3. **On-Behalf-Of (OBO) Flow**: Middle-tier API calling downstream API on behalf of an authenticated user.
