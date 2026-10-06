<#
.SYNOPSIS
    Resets an AD User Password.

.DESCRIPTION
    Resets password and forces change at next logon.
    SAFEGUARDS: High ConfirmImpact. Logs action.

.EXAMPLE
    .\Reset-Password.ps1 -Identity "jdoe" -NewPassword (Read-Host -AsSecureString) -TargetEnvironment Test

.PARAMETER TargetEnvironment
    Requires 'Test' or 'Prod'.

.NOTES
    Security Domain: Operations
    Created: 2026-01-15T13:13:20
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-OnPrem-002](../../HowTo/Scripts/KB-OnPrem-002-ResetPassword.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [Parameter(Mandatory=$true)]
    [string]$Identity,

    [Parameter(Mandatory=$true)]
    [securestring]$NewPassword,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test"
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
}

Process {
    Write-Log "Starting password reset for $Identity"
    if ($TargetEnvironment -eq "Test") {
        Write-Host "TEST: Would reset password for $Identity." -ForegroundColor Yellow
        return
    }

    if ($PSCmdlet.ShouldProcess($Identity, "Set-ADAccountPassword & Set-ADUser (ChangeAtLogon)")) {
        Set-ADAccountPassword -Identity $Identity -NewPassword $NewPassword -Reset
        Set-ADUser -Identity $Identity -ChangePasswordAtLogon $true
        Write-Host "Password reset complete." -ForegroundColor Green
    }
}
