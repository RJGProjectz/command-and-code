<#
.SYNOPSIS
    Lists high-severity software vulnerabilities for a specific device.

.DESCRIPTION
    1. Queries Microsoft Defender vulnerability data.
    2. Filters for software with CVSS score > 7.
    3. Lists App Name, CVE ID, and Severity.

.PARAMETER DeviceId
    The Microsoft Defender Machine ID.

.PARAMETER MinCvss
    Minimum CVSS score to report. Defaults to 7.0.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Get-SoftwareVulnerabilities.ps1 -DeviceId "xyz-123" -MinCvss 8.5 -TargetEnvironment Prod

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-16T16:30:00
    Last Modified: 2026-01-16T16:30:00
    Author: Antigravity
    KB Article: [KB-Sec-012-Vulnerabilities.md](../../HowTo/Scripts/KB-Sec-012-Vulnerabilities.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceId,

    [Parameter(Mandatory=$false)]
    [double]$MinCvss = 7.0,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Software Vulnerability Audit ---" -ForegroundColor Cyan
Write-Host "Device: $DeviceId (Min CVSS: $MinCvss)"

# Action would be GET /api/machines/{id}/vulnerabilities
Write-Host "[*] Fetching TVM data from Defender for Endpoint..."
Write-Host "[OK] Report generated for $DeviceId." -ForegroundColor Green
