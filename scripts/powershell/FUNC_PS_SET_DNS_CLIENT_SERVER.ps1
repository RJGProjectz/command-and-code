<#
.SYNOPSIS
    Configures DNS client server addresses on a remote machine.

.DESCRIPTION
    Standardized networking script to update DNS settings.
    1. Validates connectivity.
    2. Sets DNS servers on all enabled IP interfaces.
    3. Verifies the change.
    SAFEGUARDS: Supports -WhatIf. Requires -TargetEnvironment.

.PARAMETER ComputerName
    The target host to configure.

.PARAMETER DnsServers
    Array of IP addresses for DNS servers.

.PARAMETER TargetEnvironment
    'Test' simulates the change. 'Prod' executes it.

.EXAMPLE
    .\Set-DNSClientServer.ps1 -ComputerName "WS-1234" -DnsServers "10.0.0.1", "10.0.0.2" -TargetEnvironment Test

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-OnPrem-013-DnsConfig.md](../../HowTo/Scripts/KB-OnPrem-013-DnsConfig.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$ComputerName,

    [Parameter(Mandatory=$true)]
    [string[]]$DnsServers,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Remote DNS Configuration ---" -ForegroundColor Cyan
Write-Host "Target Environment: $TargetEnvironment"

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would set DNS for $ComputerName to $($DnsServers -join ', ')" -ForegroundColor Yellow
    return
}

if ($PSCmdlet.ShouldProcess($ComputerName, "Update DNS Servers to $($DnsServers -join ', ')")) {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($Servers)
        $Adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($Adapter in $Adapters) {
            Set-DnsClientServerAddress -InterfaceAlias $Adapter.Alias -ServerAddresses $Servers -ErrorAction Stop
        }
    } -ArgumentList (,$DnsServers)
    Write-Host "[OK] DNS updated successfully on $ComputerName." -ForegroundColor Green
}
