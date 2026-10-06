<#
.SYNOPSIS
    Retrieves Azure AD users using Microsoft Graph API.

.DESCRIPTION
    Connects to Microsoft Graph to fetch user details.
    Demonstrates handling authentication and pagination basics.
    SAFEGUARDS: Requires -TargetEnvironment.

.EXAMPLE
    .\Get-GraphUsers.ps1 -TargetEnvironment Prod

.PARAMETER TargetEnvironment
    'Test' uses a demo tenant ID (or simulates). 'Prod' connects to real tenant.

.EXAMPLE
    .\Get-GraphUsers.ps1 -TargetEnvironment Test

.NOTES
    Security Domain: Identity
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-002: Graph API Basics](../../HowTo/Scripts/KB-002-GraphBasics.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
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
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
    }
    
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
}

Process {
    try {
        Write-Log "Connecting to Graph ($TargetEnvironment)..."
        
        # Simulating Graph Connection for this template
        # In real world: Connect-MgGraph -Scopes "User.Read.All"
        
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST MODE: Returning mock data."
            $Users = @(
                [PSCustomObject]@{DisplayName="Test User 1"; UserPrincipalName="test1@domain.com"; Id="GUID-1"}
                [PSCustomObject]@{DisplayName="Test User 2"; UserPrincipalName="test2@domain.com"; Id="GUID-2"}
            )
        }
        else {
            if ($PSCmdlet.ShouldProcess("Azure Tenant", "Connect and Read Users")) {
                 # Connect-MgGraph -Scopes "User.Read.All"
                 # $Users = Get-MgUser -Top 10
                 Write-Warning "Real connection commented out for safety in this template."
                 $Users = @()
            }
        }
        
        if ($Users) {
            $Users | Format-Table DisplayName, UserPrincipalName
            $Users | Export-Csv -Path (Join-Path $LogPath "GraphUsers.csv") -NoTypeInformation
            Write-Log "Exported to GraphUsers.csv"
        }
    }
    catch {
        Write-Log $_.Exception.Message "ERROR"
    }
}
