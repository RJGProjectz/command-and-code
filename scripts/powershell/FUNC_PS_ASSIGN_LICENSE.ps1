<#
.SYNOPSIS
    Assigns a Microsoft 365 license to a user.

.DESCRIPTION
    Assigns a license via Microsoft Graph.
    SAFEGUARDS: Requires -TargetEnvironment. 

.PARAMETER UserId
    The UPN or ObjectId of the user.

.PARAMETER SkuId
    The SkuId of the license to assign (e.g., developerpack_e5).

.PARAMETER TargetEnvironment
    'Test' simulates the assignment. 'Prod' executes it.

.EXAMPLE
    .\Assign-License.ps1 -UserId "user@contoso.com" -SkuId "c42b9cae-ea4f-4ab7-9717-81576235ccac" -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-Azure-003: Licensing](../../HowTo/Scripts/KB-Azure-003-Licensing.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [string]$UserId,

    [Parameter(Mandatory=$true)]
    [string]$SkuId,

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
    
    Write-Log "Starting Assign-License for $UserId ($TargetEnvironment)"
}

Process {
    try {
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Would assign license $SkuId to $UserId"
            return
        }

        # Real Logic
        if ($PSCmdlet.ShouldProcess("User: $UserId", "Assign License: $SkuId")) {
            Set-MgUserLicense -UserId $UserId -AddLicenses @{SkuId = $SkuId} -RemoveLicenses @() -ErrorAction Stop
            Write-Log "Successfully assigned license $SkuId to $UserId"
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
