<#
.SYNOPSIS
    Retrieves a list of installed software from a local or remote machine.

.DESCRIPTION
    Standardized inventory tool.
    1. Queries the Registry (64-bit and 32-bit paths) for installed programs.
    2. Returns Name, Version, and Publisher.
    SAFEGUARDS: Read-only. Requires -TargetEnvironment.

.PARAMETER ComputerName
    The hostname to query. Defaults to localhost.

.PARAMETER TargetEnvironment
    Standard compliance parameter.

.EXAMPLE
    .\Get-SoftwareList.ps1 -ComputerName "WS-1234" -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Author: AntiGravity
    Created: 2026-01-19T08:50:00
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-OnPrem-015-SoftwareInv.md](../../HowTo/Scripts/KB-OnPrem-015-SoftwareInv.md)
#>

[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Software Inventory Audit: $ComputerName ---" -ForegroundColor Cyan

$RegPaths = @(
    "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$SoftwareList = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
    param($Paths)
    $Results = foreach ($Path in $Paths) {
        $Key = Get-Item "HKLM:\$Path" -ErrorAction SilentlyContinue
        if ($Key) {
            $Key.GetSubKeyNames() | ForEach-Object {
                $SubKey = Get-ItemProperty "HKLM:\$Path\$_" -ErrorAction SilentlyContinue
                if ($SubKey.DisplayName) {
                    [PSCustomObject]@{
                        Name      = $SubKey.DisplayName
                        Version   = $SubKey.DisplayVersion
                        Publisher = $SubKey.Publisher
                    }
                }
            }
        }
    }
    $Results | Sort-Object Name -Unique
} -ArgumentList (,$RegPaths)

if ($SoftwareList) {
    $SoftwareList | Out-GridView -Title "Installed Software on $ComputerName"
    Write-Host "[OK] Retrieved $($SoftwareList.Count) items." -ForegroundColor Green
} else {
    Write-Host "[WARN] No software found or access denied." -ForegroundColor Yellow
}
