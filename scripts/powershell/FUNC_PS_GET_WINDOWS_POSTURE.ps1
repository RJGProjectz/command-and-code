<#
.SYNOPSIS
    Performs a read-only security posture and configuration assessment on a Windows host.

.DESCRIPTION
    Audits listening network connections, non-standard running services, RDP/WinRM registry configurations, 
    and local administrative users. This script is intended for point-in-time assessments and does not make changes to the system.
    SAFEGUARDS: This script is READ-ONLY and includes mandatory -TargetEnvironment checks.

.PARAMETER TargetEnvironment
    Explicitly requires 'Test' or 'Prod'. Defaults to 'Test'.
    Operations on 'Prod' will require confirmation.

.PARAMETER LogPath
    The directory where assessment results will be logged.

.EXAMPLE
    .\Get-WindowsPosture.ps1 -TargetEnvironment Test -WhatIf

.NOTES
    Security Domain: Operations
    Author: Antigravity
    Created: 2026-01-23T15:15:00
    Last Modified: 2026-01-23T15:15:00
    KB Article: [KB-Sec-018-WindowsPosture.md](../../HowTo/Scripts/KB-Sec-018-WindowsPosture.md)
    
    CHANGE LOG:
    - 2026-01-23: Initial implementation for security posture discovery.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Audit\Logs\Posture"
)

Begin {
    # Logging Helper
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "WARNING") { $Color = "Yellow" }
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host $LogEntry -ForegroundColor $Color

        if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
        $GlobalLogFile = Join-Path $LogPath "WindowsPosture_$($TargetEnvironment)_$(Get-Date -Format 'yyyyMMdd').log"
        Add-Content -Path $GlobalLogFile -Value $LogEntry
    }

    Write-Log "Initializing Windows Posture Assessment in [$TargetEnvironment] mode."

    # Safety Check
    if ($TargetEnvironment -eq "Prod" -and $PSCmdlet.ShouldProcess("Local Host", "Execute Production Posture Audit") -eq $false) {
        Write-Warning "Assessment cancelled by user."
        exit
    }
}

Process {
    try {
        $auditResults = [PSCustomObject]@{
            Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
            HostName = $env:COMPUTERNAME
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
            InboundConnections = @()
            NonStandardServices = @()
            CriticalConfigFlags = @()
            PrivilegedUsers = @()
        }

        # 1. Audit Inbound Connections (Listening)
        Write-Log "Auditing Inbound Network Connections (Listening)..."
        $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        foreach ($conn in $connections) {
            $auditResults.InboundConnections += "$($conn.LocalAddress):$($conn.LocalPort)"
        }

        # 2. Audit Non-Standard Running Services
        Write-Log "Auditing Running Services..."
        $services = Get-Service | Where-Object { $_.Status -eq 'Running' }
        # Simplified "Non-Standard" check: exclude typical Microsoft services
        foreach ($svc in $services) {
            if ($svc.DisplayName -notmatch "Microsoft|Windows|System|Local") {
                $auditResults.NonStandardServices += "$($svc.Name) ($($svc.DisplayName))"
            }
        }

        # 3. Audit Critical Configuration Flags
        Write-Log "Auditing Registry Configuration Flags..."
        
        # RDP Check
        $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        $rdpStatus = if ($rdp.fDenyTSConnections -eq 0) { "ENABLED" } else { "DISABLED" }
        $auditResults.CriticalConfigFlags += "RDP: $rdpStatus"

        # WinRM Check
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        $auditResults.CriticalConfigFlags += "WinRM: $($winrm.Status)"

        # Firewall Check
        $fw = Get-NetFirewallProfile -Name Domain,Public,Private
        foreach ($profile in $fw) {
            $auditResults.CriticalConfigFlags += "Firewall($($profile.Name)): $($profile.Enabled)"
        }

        # 4. Audit Privileged Users
        Write-Log "Auditing Local Administrative Users..."
        $admins = Get-LocalGroupMember -Group "Administrators"
        foreach ($user in $admins) {
            $auditResults.PrivilegedUsers += "$($user.Name) ($($user.ObjectClass))"
        }

        # Output Summary
        Write-Log "Assessment complete. Summary follows:"
        $auditResults | Format-List | Out-String | Write-Log
    }
    catch {
        Write-Log "Critical Error during assessment: $($_.Exception.Message)" "ERROR"
        throw $_
    }
}

End {
    Write-Log "Windows Posture Assessment finished."
}
