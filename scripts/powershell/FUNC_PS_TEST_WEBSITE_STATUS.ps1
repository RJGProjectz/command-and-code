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
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Test-WebsiteStatus.ps1 -Urls "https://google.com", "https://bing.com" -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Created: 2026-01-16T16:35:00
    Last Modified: 2026-01-19T08:50:00
    Author: Antigravity
    KB Article: [KB-Rest-003-WebStatus.md](../../HowTo/Scripts/KB-Rest-003-WebStatus.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string[]]$Urls,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment,

    [Parameter(Mandatory=$false)]
    [string]$Token
)

Write-Host "--- mass Website Status Checker ---" -ForegroundColor Cyan

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
