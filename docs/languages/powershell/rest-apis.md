---
title: PowerShell REST APIs
platforms: [Windows, Microsoft 365, SentinelOne, Splunk]
languages: [PowerShell]
tasks: [Automation, Incident Response]
category: APIs
tags: [rest, invoke-restmethod, oauth, graph, pagination, sentinelone api, splunk api, retry]
aliases: [Invoke-RestMethod, bearer token, client credentials, api pagination, nextLink, S1 API token, splunk search api]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# PowerShell REST APIs

## GET with a bearer token

```powershell
$headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
$response = Invoke-RestMethod -Method GET -Uri 'https://api.example.com/v1/items?limit=100' -Headers $headers
```

`Invoke-RestMethod` parses JSON automatically. Use `Invoke-WebRequest` when you need status codes or response headers.

## POST a JSON body

```powershell
$body = @{ name = 'IR-2026-001'; severity = 'high'; tags = @('phishing', 'bec') } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method POST -Uri 'https://api.example.com/v1/cases' -Headers $headers -Body $body -ContentType 'application/json'
```

## Get an OAuth token (client credentials)

Entra ID app registration, e.g. for Microsoft Graph:

```powershell
$tokenParams = @{
    Method = 'POST'
    Uri    = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
    Body   = @{
        grant_type    = 'client_credentials'
        client_id     = $clientId
        client_secret = $clientSecret
        scope         = 'https://graph.microsoft.com/.default'
    }
}
$token = (Invoke-RestMethod @tokenParams).access_token
```

A hashtable `-Body` on POST is sent as `application/x-www-form-urlencoded`, which is what the token endpoint expects. Prefer certificate credentials over secrets for production apps.

## Follow pagination (Microsoft Graph)

```powershell
$uri = 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=999'
$all = while ($uri) {
    $page = Invoke-RestMethod -Uri $uri -Headers $headers
    $page.value
    $uri = $page.'@odata.nextLink'
}
```

`$select` and `$top` are inside a **single-quoted** string so PowerShell does not expand them as variables.

## SentinelOne Management API

Header format is `Authorization: ApiToken <token>`. Cursor pagination:

```powershell
$s1Headers = @{ Authorization = "ApiToken $s1Token" }
$uri = "https://$s1Console/web/api/v2.1/agents?limit=200&computerName__contains=WS-"
$agents = while ($uri) {
    $page = Invoke-RestMethod -Uri $uri -Headers $s1Headers
    $page.data
    $cursor = $page.pagination.nextCursor
    $uri = if ($cursor) { "https://$s1Console/web/api/v2.1/agents?limit=200&computerName__contains=WS-&cursor=$cursor" } else { $null }
}
$agents | Select-Object computerName, osName, agentVersion, isActive, networkStatus
```

Filter names (`computerName__contains`) and fields vary by console version — check your console's API documentation (*Help → API Doc*).

## Splunk search API

```powershell
$splunkHeaders = @{ Authorization = "Bearer $splunkToken" }
$form = @{
    search        = 'search index=wineventlog EventCode=4625 earliest=-1h | stats count by host'
    output_mode   = 'json'
}
$raw = Invoke-WebRequest -Method POST -Uri 'https://splunk01:8089/services/search/jobs/export' -Headers $splunkHeaders -Body $form
$raw.Content -split "`n" | Where-Object { $_ } | ForEach-Object { ($_ | ConvertFrom-Json).result }
```

The export endpoint streams one JSON object per line. The search string must start with `search` (or `|` for generating commands).

## TLS and certificates

```powershell
# Windows PowerShell 5.1 on older systems may default to TLS 1.0
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
```

PowerShell 7: `-SkipCertificateCheck` exists for lab use; in production trust the issuing CA instead.

## Read the error body

```powershell
try {
    Invoke-RestMethod -Uri $uri -Headers $headers -ErrorAction Stop
} catch {
    $status = $_.Exception.Response.StatusCode
    Write-Warning "HTTP $([int]$status): $($_.ErrorDetails.Message)"
}
```

## Retry on throttling (429) and transient errors

```powershell
function Invoke-ApiWithRetry {
    param([string]$Uri, [hashtable]$Headers, [int]$MaxAttempts = 5)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -ErrorAction Stop
        } catch {
            $code = [int]$_.Exception.Response.StatusCode
            if ($attempt -eq $MaxAttempts -or ($code -ne 429 -and $code -lt 500)) { throw }
            $retryAfter = $_.Exception.Response.Headers['Retry-After']
            $delay = if ($retryAfter) { [int]"$retryAfter" } else { [math]::Pow(2, $attempt) }
            Write-Verbose "HTTP $code, retrying in $delay s (attempt $attempt)"
            Start-Sleep -Seconds $delay
        }
    }
}
```

The `Retry-After` header object differs between 5.1 and 7; the string cast handles both for the usual seconds value.

## Secrets

Never hard-code tokens. Options, best first: managed identity / certificate auth → **SecretManagement** (`Get-Secret -Name S1Token -AsPlainText`) → environment variable set by the scheduler → `Get-Credential` for interactive use.

## Related

- [Python HTTP and APIs](../python/http-apis.md)
- [Defender XDR API examples](../../platforms/microsoft-365/defender.md)
- [Error handling](error-handling.md)

## Sources

- [Invoke-RestMethod](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [Microsoft identity platform client credentials flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft Graph paging](https://learn.microsoft.com/graph/paging)
- [Splunk REST API: search/jobs/export](https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch)
