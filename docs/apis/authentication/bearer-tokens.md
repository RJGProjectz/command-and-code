---
title: OAuth 2.0 Bearer Token Authentication Flow
type: entry
platforms:
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
  - Bash
  - REST API
tasks:
  - Automation
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - api
  - oauth2
  - authentication
  - bearer-token
---

# OAuth 2.0 Bearer Token Authentication Flow

Standardized pattern for acquiring application access tokens from Microsoft Entra ID using the OAuth 2.0 Client Credentials Grant (`client_credentials`).

## Identity Provider Endpoint

- **URI**: `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`
- **Method**: `POST`
- **Content-Type**: `application/x-www-form-urlencoded`

---

## Copy-Ready Implementations

### PowerShell (`Invoke-RestMethod`)

```powershell
function Get-EntraBearerToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TenantId,
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret,
        [string]$Scope = "https://graph.microsoft.com/.default"
    )

    $TokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $Body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $Scope
    }

    $Response = Invoke-RestMethod -Method Post -Uri $TokenUri -ContentType "application/x-www-form-urlencoded" -Body $Body
    return $Response.access_token
}

# Example usage:
# $Token = Get-EntraBearerToken -TenantId "contoso.onmicrosoft.com" -ClientId "xxx" -ClientSecret "yyy"
```

### Bash (`curl` + `jq`)

```bash
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default" | jq -r '.access_token')
```

---

## Security Safeguards

- Never hardcode secrets in scripts. Store secrets in Azure Key Vault, PowerShell SecretManagement, or system environment variables.
- Scope applications to least-privilege role permissions (e.g., `AuditLog.Read.All` instead of `Directory.ReadWrite.All`).
