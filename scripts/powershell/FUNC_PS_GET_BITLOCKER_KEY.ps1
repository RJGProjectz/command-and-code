<#
.SYNOPSIS
    Retrieves the BitLocker recovery password for a computer.

.DESCRIPTION
    Queries Active Directory for the msFVE-RecoveryPassword attribute.
    SAFEGUARDS: Read-only. Requires -TargetEnvironment.

.PARAMETER ComputerName
    The name of the computer to search for.

.PARAMETER TargetEnvironment
    'Test' simulates the query. 'Prod' performs it.

.EXAMPLE
    .\Get-BitlockerKey.ps1 -ComputerName "WS-1234" -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-OnPrem-007: BitLocker Recovery](../../HowTo/Scripts/KB-OnPrem-007-Bitlocker.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [string]$ComputerName,

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
    
    Write-Log "Starting Get-BitlockerKey for $ComputerName ($TargetEnvironment)"
}

Process {
    try {
        if ($TargetEnvironment -eq "Test") {
            Write-Log "TEST: Would query AD for Bitlocker recovery information for $ComputerName"
            return
        }

        # Real Logic
        if ($PSCmdlet.ShouldProcess("Active Directory", "Read BitLocker Info for $ComputerName")) {
            $RecoveryInfo = Get-ADObject -Filter {objectClass -eq 'msFVE-RecoveryInformation'} -Properties 'msFVE-RecoveryPassword', 'DistinguishedName' 
            
            # Note: A real implementation needs to match the child object to the computer. 
            # Often BitLocker objects are children of the Computer object.
            # Simplified approach: Find computer, then look for children.
            
            $Computer = Get-ADComputer -Identity $ComputerName -ErrorAction Stop
            $BLObjects = Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase $Computer.DistinguishedName -Properties msFVE-RecoveryPassword

            if ($BLObjects) {
                foreach ($obj in $BLObjects) {
                    Write-Host "Recovery Password ID: $($obj.Name)" -ForegroundColor Green
                    Write-Host "Password: $($obj.'msFVE-RecoveryPassword')" -ForegroundColor Yellow
                    Write-Log "Retrieved key for $($obj.Name)"
                }
            }
            else {
                Write-Log "No BitLocker recovery information found for $ComputerName" "WARN"
            }
        }
    }
    catch {
        Write-Log "Error: $($_.Exception.Message)" "ERROR"
        # throw $_ # Optional: Don't crash on read fail
    }
}

End {
    Write-Log "Completed."
}
