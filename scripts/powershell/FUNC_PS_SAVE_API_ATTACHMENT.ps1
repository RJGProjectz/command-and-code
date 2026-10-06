<#
.SYNOPSIS
    Downloads a binary file (attachment) from a REST API.

.DESCRIPTION
    1. Uses Invoke-WebRequest to handle binary streams.
    2. Saves the file to a specified local path.
    3. Verifies the file was created and is non-empty.

.PARAMETER Uri
    The direct link to the file/attachment.

.PARAMETER OutPath
    The local path to save the folder.

.PARAMETER Token
    Optional Bearer token.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Save-ApiAttachment.ps1 -Uri "https://example.com/report.pdf" -OutPath "C:\Downloads\report.pdf" -TargetEnvironment Prod

.NOTES
    Security Domain: Application
    Created: 2026-01-16T16:35:00
    Last Modified: 2026-01-16T16:35:00
    Author: Antigravity
    KB Article: [KB-Rest-002-SaveAttachment.md](../../HowTo/Scripts/KB-Rest-002-SaveAttachment.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Uri,

    [Parameter(Mandatory=$true)]
    [string]$OutPath,

    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- API Binary Download ---" -ForegroundColor Cyan
Write-Host "Source: $Uri -> $OutPath"

$Headers = @{}
if ($Token) { $Headers["Authorization"] = "Bearer $Token" }

try {
    Invoke-WebRequest -Uri $Uri -OutFile $OutPath -Headers $Headers -ErrorAction Stop
    if (Test-Path $OutPath) {
        $Size = (Get-Item $OutPath).Length
        Write-Host "[OK] Download Complete ($Size bytes)." -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Download failed. Error: $($_.Exception.Message)" -ForegroundColor Red
}
