<#
.SYNOPSIS
    Mass port connectivity checker for multiple hosts and ports.

.DESCRIPTION
    Standardized network auditing tool.
    1. Tests TCP connectivity to a list of ports across a list of hosts.
    2. Outputs a clean status report.
    SAFEGUARDS: Read-only probes.

.PARAMETER Computers
    Array of hostnames or IP addresses.

.PARAMETER Ports
    Array of port numbers to test.

.PARAMETER TargetEnvironment
    Standard compliance parameter.

.EXAMPLE
    .\Test-NetConn.ps1 -Computers "svr01", "svr02" -Ports 80, 443, 3389 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-OnPrem-014-NetConn.md](../../HowTo/Scripts/KB-OnPrem-014-NetConn.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Computers,

    [Parameter(Mandatory=$true)]
    [int[]]$Ports,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Multi-Host Port Connectivity Test ---" -ForegroundColor Cyan

$Results = foreach ($Computer in $Computers) {
    foreach ($Port in $Ports) {
        Write-Host "[*] Testing $Computer : $Port..." -NoNewline
        $Test = Test-NetConnection -ComputerName $Computer -Port $Port -WarningAction SilentlyContinue
        if ($Test.TcpTestSucceeded) {
            Write-Host " [SUCCESS]" -ForegroundColor Green
            [PSCustomObject]@{ Computer = $Computer; Port = $Port; Status = "Open" }
        } else {
            Write-Host " [FAILED]" -ForegroundColor Red
            [PSCustomObject]@{ Computer = $Computer; Port = $Port; Status = "Closed/Filtered" }
        }
    }
}

$Results | Format-Table -AutoSize
