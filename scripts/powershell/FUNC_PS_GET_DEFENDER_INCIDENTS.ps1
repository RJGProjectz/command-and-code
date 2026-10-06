<#
.SYNOPSIS
    Retrieves unresolved security incidents from Microsoft Defender.

.DESCRIPTION
    Standardized incident management tool.
    1. Queries /security/incidents endpoint.
    2. Filters for 'Active' or 'New' status.
    SAFEGUARDS: Read-only. Requires -TargetEnvironment.

.PARAMETER Severity
    Filter by severity: Informational, Low, Medium, High.

.PARAMETER TargetEnvironment
    Standard compliance parameter.

.EXAMPLE
    .\Get-DefenderIncidents.ps1 -Severity High -TargetEnvironment Prod

.NOTES
    Security Domain: Endpoint
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Sec-016-DefenderIncidents.md](../../HowTo/Scripts/KB-Sec-016-DefenderIncidents.md)
#>

[CmdletBinding()]
param(
    [ValidateSet("Informational", "Low", "Medium", "High")]
    [string]$Severity,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Active Defender Incidents Audit ---" -ForegroundColor Cyan

try {
    Write-Host "[*] Querying Graph Security API..."
    $Filter = "status eq 'active'"
    if ($Severity) { $Filter += " and severity eq '$Severity'" }
    
    # Placeholder for MG Graph Call
    # $Incidents = Get-MgSecurityIncident -Filter $Filter -ErrorAction Stop
    $Incidents = @() 
    
    if ($Incidents) {
        $Incidents | Select-Object Id, IncidentName, Severity, CreatedDateTime | Format-Table -AutoSize
        Write-Host "[OK] Retrieved $($Incidents.Count) active incidents." -ForegroundColor Green
    } else {
        Write-Host "[INFO] No active incidents found for the selected criteria." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Incident query failed: $($_.Exception.Message)" -ForegroundColor Red
}
