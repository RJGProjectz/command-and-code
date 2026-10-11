<#
.SYNOPSIS
    Validates multiple website URLs for HTTP 200 (OK) status.

.DESCRIPTION
    1. Takes an array of URLs or a file path.
    2. Tests each for basic reachability.
    3. Outputs a tabular report of results.

.PARAMETER Urls
    Array of URL strings.

.PARAMETER TargetEnvironment
    'Test' (default) simulates. 'Prod' executes.

.EXAMPLE
    .\Test-WebsiteStatus.ps1 -Urls "https://google.com", "https://bing.com" -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Created: 2026-01-16T16:35:00
    Last Modified: 2026-01-19T08:50:00
    Author: Antigravity
    Documentation: [HTTP/HTTPS Protocol Mechanics & Headers](../../docs/fundamentals/networking/http-https.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string[]]$Urls,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$false)]
    [string]$Token
)

Write-Host "--- mass Website Status Checker ---" -ForegroundColor Cyan

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would send HEAD requests to $($Urls -join ', ')" -ForegroundColor Yellow
    return
}

$Results = foreach ($Url in $Urls) {
    Write-Host "[*] Testing $Url..." -NoNewline
    try {
        $Resp = Invoke-WebRequest -Uri $Url -Method Head -TimeoutSec 5 -ErrorAction Stop
        Write-Host " [OK] ($($Resp.StatusCode))" -ForegroundColor Green
        [PSCustomObject]@{ Url = $Url; Status = $Resp.StatusCode; Result = "UP" }
    } catch {
        Write-Host " [FAIL]" -ForegroundColor Red
        [PSCustomObject]@{ Url = $Url; Status = "ERR"; Result = "DOWN" }
    }
}

$Results | Format-Table -AutoSize
