<#
.SYNOPSIS
    Adds a user to an Active Directory group.

.DESCRIPTION
    Safely adds a user to a specified group.
    Checks if the user is already a member before attempting addition.
    SAFEGUARDS: Supports -WhatIf. Requires -TargetEnvironment.

.PARAMETER Identity
    The user to add (SamAccountName, DN, etc.).

.PARAMETER Group
    The group to add the user to.

.PARAMETER TargetEnvironment
    'Test' simulates the action. 'Prod' performs it.

.EXAMPLE
    .\Add-ADGroupMember.ps1 -Identity "jdoe" -Group "VPN-Users" -TargetEnvironment Test

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-OnPrem-006: Group Management](../../HowTo/Scripts/KB-OnPrem-006-GroupManagement.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [string]$Identity,

    [Parameter(Mandatory=$true)]
    [string]$Group,

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
    
    Write-Log "Starting Add-ADGroupMember for $Identity -> $Group ($TargetEnvironment)"
}

Process {
    try {
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Would check if $Identity is in $Group"
            Write-Log "TEST: Would add $Identity to $Group if not present"
            return
        }

        # Real Logic
        $UserObj = Get-ADUser -Identity $Identity -ErrorAction Stop
        $GroupObj = Get-ADGroup -Identity $Group -ErrorAction Stop

        # Check membership
        $Members = Get-ADGroupMember -Identity $GroupObj -Recursive:$false | Select-Object -ExpandProperty SamAccountName
        if ($Members -contains $UserObj.SamAccountName) {
            Write-Log "User $Identity is already a member of $Group." "WARN"
        }
        else {
            if ($PSCmdlet.ShouldProcess("Group: $($GroupObj.Name)", "Add Member: $($UserObj.SamAccountName)")) {
                Add-ADGroupMember -Identity $GroupObj -Members $UserObj -ErrorAction Stop
                Write-Log "Successfully added $Identity to $Group."
            }
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
