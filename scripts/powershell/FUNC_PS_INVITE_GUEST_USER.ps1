<#
.SYNOPSIS
    Invites an external guest user to the Azure AD tenant.

.DESCRIPTION
    Standardized B2B invitation workflow.
    SAFEGUARDS: Requires -TargetEnvironment.

.PARAMETER EmailAddress
    The email address of the guest to invite.

.PARAMETER DisplayName
    The display name for the guest user.

.PARAMETER TargetEnvironment
    'Test' simulates the invitation. 'Prod' executes it.

.EXAMPLE
    .\Invite-GuestUser.ps1 -EmailAddress "partner@external.com" -DisplayName "John Partner" -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-Azure-002: Guest Access](../../HowTo/Scripts/KB-Azure-002-GuestAccess.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [string]$EmailAddress,

    [Parameter(Mandatory=$true)]
    [string]$DisplayName,

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
    
    Write-Log "Starting Invite-GuestUser for $EmailAddress ($TargetEnvironment)"
}

Process {
    try {
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Would invite $EmailAddress as guest."
            return
        }

        # Real Logic
        if ($PSCmdlet.ShouldProcess("Tenant", "Invite Guest: $EmailAddress")) {
            $Invitation = New-MgInvitation -InvitedUserEmailAddress $EmailAddress `
                                           -InvitedUserDisplayName $DisplayName `
                                           -InviteRedirectUrl "https://myapps.microsoft.com" `
                                           -SendInvitationMessage:$true `
                                           -ErrorAction Stop
            
            Write-Log "Invitation sent. Status: $($Invitation.Status)"
            Write-Log "Redemption URL: $($Invitation.InviteRedeemUrl)"
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
