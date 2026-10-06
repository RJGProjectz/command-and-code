<#
.SYNOPSIS
    Submits a JSON payload to a REST API via POST.

.DESCRIPTION
    1. Handles JSON conversion.
    2. Supports Bearer Token authentication.
    3. Includes error handling for 4xx/5xx responses.

.PARAMETER Uri
    The API Endpoint URI.

.PARAMETER Payload
    The hashtable or object to convert to JSON.

.PARAMETER Token
    Bearer token for authentication.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    $User = @{ name="John"; job="Engineer" }
    .\Submit-GenericPost.ps1 -Uri "https://reqres.in/api/users" -Payload $User -TargetEnvironment Test

.NOTES
    Security Domain: Application
    Created: 2026-01-16T16:35:00
    Last Modified: 2026-01-16T16:35:00
    Author: Antigravity
    KB Article: [KB-Rest-001-GenericPost.md](../../HowTo/Scripts/KB-Rest-001-GenericPost.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [Parameter(Mandatory=$true)]
    [object]$Payload,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Generic API POST ---" -ForegroundColor Cyan
Write-Host "Target: $Uri ($TargetEnvironment)"

$Headers = @{ "Content-Type" = "application/json" }
if ($Token) { $Headers["Authorization"] = "Bearer $Token" }

$Json = $Payload | ConvertTo-Json

try {
    $Response = Invoke-RestMethod -Uri $Uri -Method Post -Body $Json -Headers $Headers -ErrorAction Stop
    Write-Host "[OK] Success (200/201 Created)" -ForegroundColor Green
    return $Response
} catch {
    Write-Host "[FAIL] API Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        Write-Host "[ERROR BODY]: $($_.Exception.Response.Content)" -ForegroundColor Gray
    }
}
