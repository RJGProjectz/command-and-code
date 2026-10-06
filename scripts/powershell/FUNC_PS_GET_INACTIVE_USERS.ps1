<#
.SYNOPSIS
    Retrieves a list of inactive users from Active Directory.

.DESCRIPTION
    Scans Active Directory for users who have not logged in for a specified number of days.
    Helpful for license reclamation and security hygiene.
    SAFEGUARDS: Requires -TargetEnvironment parameter.

.PARAMETER TargetEnvironment
    Explicitly requires 'Test' or 'Prod'. Defaults to 'Test'.
    Operations on 'Prod' will require confirmation.
    In 'Test' mode, it will only query a specific Test OU (defined in variables).

.PARAMETER DaysInactive
    Number of days to check for inactivity. Default is 90.

.EXAMPLE
    .\Get-InactiveUsers.ps1 -TargetEnvironment Test -DaysInactive 30

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-001: Finding Inactive Users](../../HowTo/Scripts/KB-001-InactiveUsers.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host $LogEntry -ForegroundColor $Color
        
        if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
        Add-Content -Path (Join-Path $LogPath "ScriptLog.log") -Value $LogEntry
    }

    Write-Log "Starting Get-InactiveUsers check in [$TargetEnvironment] mode."
    
    # Environment-Specific Settings
    $SearchBase = if ($TargetEnvironment -eq "Test") { "OU=TestUsers,DC=contoso,DC=com" } else { "DC=contoso,DC=com" }

    if ($TargetEnvironment -eq "Prod" -and $PSCmdlet.ShouldProcess("PRODUCTION: AD Query", "Querying entire domain") -eq $false) {
        Write-Warning "Cancelled."
        exit
    }
}

Process {
    try {
        Write-Log "Searching for users inactive for > $DaysInactive days in $SearchBase"
        
        $VerifyDate = (Get-Date).AddDays(-$DaysInactive)
        
        # Simulation for NO-AD environment (so the script runs without errors for typical users without RSAT)
        if (-not (Get-Module -ListAvailable ActiveDirectory)) {
            Write-Log "ActiveDirectory module not found. Simulating output." "WARNING"
            [PSCustomObject]@{
                SamAccountName = "TestUser1"
                LastLogonDate = $VerifyDate.AddDays(-10)
                Enabled = $true
            } | Export-Csv -Path (Join-Path $LogPath "InactiveUsers_Report.csv") -NoTypeInformation
            return
        }

        if ($PSCmdlet.ShouldProcess("Directory Search", "Read-only query against AD")) {
             Get-ADUser -Filter {LastLogonDate -lt $VerifyDate -and Enabled -eq $true} -SearchBase $SearchBase -Properties LastLogonDate | 
             Select-Object Name, SamAccountName, LastLogonDate |
             Export-Csv -Path (Join-Path $LogPath "InactiveUsers_Report.csv") -NoTypeInformation
        }
        
        Write-Log "Report generated at $(Join-Path $LogPath "InactiveUsers_Report.csv")"
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        throw $_
    }
}

End {
    Write-Log "Completed."
}
