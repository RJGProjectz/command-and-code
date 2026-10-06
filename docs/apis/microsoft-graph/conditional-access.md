---
title: Microsoft Graph API — Conditional Access Policies
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
  - REST API
tasks:
  - Administration
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - api
  - graph
  - entra
  - conditional-access
---

# Microsoft Graph API — Conditional Access Policies

Queries, audits, and programmatically verifies Entra ID Conditional Access policies across the tenant.

## Endpoint & Permissions

- **Method**: `GET`
- **URI**: `https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`
- **Authentication**: OAuth 2.0 Bearer token
- **Required Permissions**: `Policy.Read.All` (Application or Delegated)

---

## Copy-Ready PowerShell

```powershell
# Prerequisites: Valid token with Policy.Read.All
$Url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$Headers = @{ "Authorization" = "Bearer $Token" }

$Policies = Invoke-RestMethod -Method Get -Uri $Url -Headers $Headers

# Output policy state and targeted controls
$Policies.value | Select-Object id, displayName, state,
    @{Name="GrantControls"; Expression={($_.grantControls.builtInControls -join ', ')}},
    @{Name="ClientApps"; Expression={($_.conditions.clientAppTypes -join ', ')}}
```

---

## Operational Use Cases

1. **Drift Detection**: Detect unauthorized administrative disabling of mandatory MFA policies or legacy authentication blocking.
2. **Posture Assurance**: Programmatically confirm that baseline security policies apply to all cloud apps without gaps.
