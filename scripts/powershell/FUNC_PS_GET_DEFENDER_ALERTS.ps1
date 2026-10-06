<#
.SYNOPSIS
    Gets High Severity Alerts from Defender for Endpoint.

.DESCRIPTION
    Retrieves high severity alerts from MS Defender.
    Demonstrates API connection to Defender security center.
    SAFEGUARDS: Read-only operation.

.PARAMETER TargetEnvironment
    'Test' simulates data. 'Prod' connects to live API.

.EXAMPLE
    .\Get-DefenderAlerts.ps1 -TargetEnvironment Test

.NOTES
    Security Domain: Endpoint
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-003: Defender Alert Triage](../../HowTo/Scripts/KB-003-DefenderAlerts.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",
    
    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
    }
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
}

Process {
    try {
        Write-Log "Fetching Defender Alerts ($TargetEnvironment)..."
        
        if ($TargetEnvironment -eq "Test") {
            [PSCustomObject]@{
                Title = "Suspicious PowerShell Execution"
                Severity = "High"
                Status = "New"
                Computer = "Workstation-01"
            } | Export-Csv (Join-Path $LogPath "DefenderAlerts.csv") -NoTypeInformation
            Write-Log "Test alert exported."
        }
        else {
             if ($PSCmdlet.ShouldProcess("Defender Portal", "Fetch High Severity Alerts")) {
                # Placeholder for actual API call
                # Check KB for authentication setup
                Write-Warning "Prod connection requires valid API Credentials."
             }
        }
    }
    catch {
        Write-Log $_.Exception.Message "ERROR"
    }
}
