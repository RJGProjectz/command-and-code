---
title: Microsoft Graph API — User Authentication Methods
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
  - REST API
tasks:
  - Administration
  - Incident Response
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - graph
  - mfa
  - fido2
  - auth-methods
---

# Microsoft Graph API — User Authentication Methods

Audits registered Multi-Factor Authentication (MFA) methods, FIDO2 security keys, Microsoft Authenticator apps, and phone numbers for Entra ID accounts.

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods`
- **Authentication**: OAuth 2.0 Bearer token
- **Required Application Permission**: `UserAuthenticationMethod.Read.All`

---

## Copy-Ready PowerShell

```powershell
param(
    [Parameter(Mandatory=$true)][string]$UserPrincipalName,
    [Parameter(Mandatory=$true)][string]$Token
)

$Uri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName/authentication/methods"
$Headers = @{ "Authorization" = "Bearer $Token" }

$Methods = Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
$Methods.value | Select-Object id, @{Name="MethodType"; Expression={$_['@odata.type']}}, phoneType, phoneNumber
```

---

## Operational Use Cases

- **MFA Persistence Inspection**: Verify if an attacker added an unauthorized secondary Authenticator app or SMS phone number to an account during a session hijacking incident.
- **FIDO2 / Phishing-Resistant Migration Audit**: Audit accounts missing hardware security keys or authenticator push notifications.
