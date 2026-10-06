<#
.SYNOPSIS
    Retrieves recent Error and Warning events from the System and Application event logs.

.DESCRIPTION
    Standardized auditing script to find recent failures.
    1. Queries the last X hours of logs.
    2. Filters for Error and Warning levels.
    3. Outputs a summary of event sources and messages.
    SAFEGUARDS: Read-only. Requires -TargetEnvironment.

.PARAMETER Hours
    Number of hours to look back. Defaults to 24.

.PARAMETER TargetEnvironment
    'Test' and 'Prod' both perform the same read action for consistency.

.EXAMPLE
    .\Get-EventLogErrors.ps1 -Hours 4 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-OnPrem-012-EventAudit.md](../../HowTo/Scripts/KB-OnPrem-012-EventAudit.md)
#>

[CmdletBinding()]
param(
    [int]$Hours = 24,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

$StartTime = (Get-Date).AddHours(-$Hours)
Write-Host "--- Event Log Error Audit (Last $Hours Hours) ---" -ForegroundColor Cyan
Write-Host "Target Environment: $TargetEnvironment"

$Logs = "System", "Application"
$Events = foreach ($Log in $Logs) {
    Write-Host "[*] Searching $Log log..."
    Get-WinEvent -FilterHashtable @{LogName=$Log; Level=1,2,3; StartTime=$StartTime} -ErrorAction SilentlyContinue
}

if ($Events) {
    $Events | Select-Object TimeCreated, LogName, ProviderName, LevelDisplayName, Message | 
              Sort-Object TimeCreated -Descending | 
              Out-GridView -Title "Event Log Errors - Last $Hours Hours"
    Write-Host "[OK] Found $($Events.Count) events. Displaying in GridView." -ForegroundColor Green
} else {
    Write-Host "[INFO] No Error/Warning events found in the specified timeframe." -ForegroundColor Yellow
}
