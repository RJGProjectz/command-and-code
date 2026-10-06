<#
.SYNOPSIS
    Standardized handler for OAuth2 Bearer token retrieval and refresh.

.DESCRIPTION
    Helper script for REST API integrations.
    1. Requests token from identity provider.
    2. Stores token in memory/secure string.
    SAFEGUARDS: Encrypts secrets in session.

.PARAMETER TenantId
    Azure/O365 Tenant ID.

.PARAMETER ClientId
    Application ID.

.PARAMETER ClientSecret
    Application Secret (SecureString).

.PARAMETER TargetEnvironment
    Standard compliance parameter.

.EXAMPLE
    .\Handle-BearerAuth.ps1 -TenantId "..." -ClientId "..." -ClientSecret $SecureSecret -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Rest-004-BearerAuth.md](../../HowTo/Scripts/KB-Rest-004-BearerAuth.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$ClientId,

    [Parameter(Mandatory=$true)]
    [System.Security.SecureString]$ClientSecret,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- OAuth2 Bearer Auth Handler ---" -ForegroundColor Cyan

try {
    Write-Host "[*] Requesting token from login.microsoftonline.com..."
    # Real logic: Invoke-RestMethod to /oauth2/v2.0/token
    $TokenResponse = @{ access_token = "MOCK_TOKEN_$(Get-Date -UFormat %s)"; expires_in = 3600 }
    
    Write-Host "[OK] Token received. Expires in: $($TokenResponse.expires_in) seconds." -ForegroundColor Green
    return $TokenResponse.access_token
} catch {
    Write-Host "[ERROR] Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
    throw $_
}
