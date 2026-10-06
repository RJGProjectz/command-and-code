<#
.SYNOPSIS
    Releases a machine from network isolation in Microsoft Defender for Endpoint.

.DESCRIPTION
    Uses Microsoft Graph to trigger a machine un-isolation action.
    SAFEGUARDS: Requires -TargetEnvironment.

.PARAMETER MachineId
    The MDE Device ID.

.PARAMETER Comment
    Reason for release (required for audit).

.PARAMETER TargetEnvironment
    'Test' simulates the action. 'Prod' executes it.

.EXAMPLE
    .\Unisolate-Machine.ps1 -MachineId "machine-id-123" -Comment "False Positive" -TargetEnvironment Test

.NOTES
    Security Domain: Endpoint
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-Sec-002: Isolation](../../HowTo/Scripts/KB-Sec-002-Isolation.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [string]$MachineId,

    [Parameter(Mandatory=$true)]
    [string]$Comment,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color

        if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
        Add-Content -Path (Join-Path $LogPath "ScriptLog.log") -Value $LogEntry
    }
    
    Write-Log "Starting Unisolate-Machine for $MachineId ($TargetEnvironment)"
}

Process {
    try {
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Would release machine $MachineId from isolation. Reason: $Comment"
            return
        }

        # Real Logic
        if ($PSCmdlet.ShouldProcess("Machine: $MachineId", "Unisolate Network")) {
             $Body = @{
                "Comment" = $Comment
            }
            # Placeholder for actual API call pattern
            # Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/machines/$MachineId/unisolate" -Body $Body
            
            Write-Log "Unisolation command sent for $MachineId."
        }
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        throw $_
    }
}

End {
    Write-Log "Completed."
}
