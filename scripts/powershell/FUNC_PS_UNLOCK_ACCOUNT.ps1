<#
.SYNOPSIS
    Unlocks a specified Active Directory user account.

.DESCRIPTION
    Checks the account status and unlocks it if locked.
    SAFEGUARDS: Requires -TargetEnvironment.

.PARAMETER TargetEnvironment
    'Test' simulates the unlock. 'Prod' performs it.

.EXAMPLE
    .\Unlock-Account.ps1 -Identity "jdoe" -TargetEnvironment Test

.NOTES
    Security Domain: Operations
    Created: 2026-01-15T13:13:14
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-OnPrem-001](../../HowTo/Scripts/KB-OnPrem-001-UnlockAccount.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [string]$Identity,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",
    
    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    $ErrorActionPreference = "Stop"
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
}

Process {
    try {
        Write-Log "Processing unlock for $Identity in $TargetEnvironment"
        
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Simulating unlock for $Identity. Account would be unlocked."
            return
        }

        if ($PSCmdlet.ShouldProcess($Identity, "Unlock-ADAccount")) {
            Unlock-ADAccount -Identity $Identity
            Write-Log "Successfully unlocked $Identity"
        }
    }
    catch {
        Write-Log $_.Exception.Message "ERROR"
        throw $_
    }
}
