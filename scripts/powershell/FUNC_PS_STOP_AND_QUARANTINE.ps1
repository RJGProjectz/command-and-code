<#
.SYNOPSIS
    Remote process termination and file quarantine via Microsoft Defender for Endpoint.

.DESCRIPTION
    High-impact remediation tool.
    1. Triggers process kill on the target machine.
    2. Quarantines the associated file hash.
    SAFEGUARDS: Supports -Confirm for Prod. Requires -TargetEnvironment.

.PARAMETER MachineId
    MDE Device ID.

.PARAMETER Sha1
    The SHA1 hash of the file to quarantine.

.PARAMETER Comment
    Reason for the action (Required).

.PARAMETER TargetEnvironment
    'Test' simulates. 'Prod' executes.

.EXAMPLE
    .\Stop-And-Quarantine.ps1 -MachineId "mde-id-123" -Sha1 "da39a3ee5e6b4b0d3255bfef95601890afd80709" -Comment "Malicious binary" -TargetEnvironment Test

.NOTES
    Security Domain: Endpoint
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Sec-013-StopQuarantine.md](../../HowTo/Scripts/KB-Sec-013-StopQuarantine.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)]
    [string]$MachineId,

    [Parameter(Mandatory=$true)]
    [string]$Sha1,

    [Parameter(Mandatory=$true)]
    [string]$Comment,

    [Parameter(Mandatory=$true)]
    [string]$Token,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- MDE Stop & Quarantine Action ---" -ForegroundColor Cyan

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would kill process and quarantine hash $Sha1 on machine $MachineId" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess("Machine: $MachineId", "Quarantine Hash: $Sha1")) {
    try {
        $Uri = "https://graph.microsoft.com/v1.0/security/microsoft.graph.defender/machines/$MachineId/stopAndQuarantineFile"
        $Body = @{
            "Action" = "StopAndQuarantineFile"
            "Comment" = $Comment
            "Sha1" = $Sha1
        } | ConvertTo-Json

        $Header = @{
            "Authorization" = "Bearer $Token"
            "Content-Type"  = "application/json"
        }

        Write-Host "[*] Sending Stop and Quarantine command via Microsoft Graph..." -ForegroundColor Yellow
        $Response = Invoke-RestMethod -Uri $Uri -Method Post -Headers $Header -Body $Body

        Write-Host "[OK] Quarantine command sent successfully. Action ID: $($Response.id)" -ForegroundColor Green
        return $Response
    } catch {
        Write-Host "[FAIL] Error sending command: $($_.Exception.Message)" -ForegroundColor Red
        throw $_
    }
}
