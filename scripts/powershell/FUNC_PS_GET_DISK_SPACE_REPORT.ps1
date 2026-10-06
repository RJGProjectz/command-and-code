<#
.SYNOPSIS
    Generates a disk space report for a local or remote computer.

.DESCRIPTION
    1. Retrieves all logical disks.
    2. Calculates free space percentage.
    3. Highlights volumes below a certain threshold.

.PARAMETER ComputerName
    The name of the computer. Defaults to localhost.

.PARAMETER Threshold
    Percentage threshold for "Low Space" warnings. Defaults to 10.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Get-DiskSpaceReport.ps1 -ComputerName "Server01" -Threshold 15 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-01-16T16:20:00
    Last Modified: 2026-01-16T16:20:00
    Author: Antigravity
    KB Article: [KB-OnPrem-010-DiskReport.md](../../HowTo/Scripts/KB-OnPrem-010-DiskReport.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$false)]
    [int]$Threshold = 10,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- Disk Space Report ---" -ForegroundColor Cyan
Write-Host "Target: $ComputerName (Threshold: $Threshold%)"

try {
    $Disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName -Filter "DriveType=3" -ErrorAction Stop
    $Report = foreach ($Disk in $Disks) {
        $FreeGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
        $SizeGB = [math]::Round($Disk.Size / 1GB, 2)
        $PercentFree = [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 2)
        
        $Status = "OK"
        if ($PercentFree -lt $Threshold) { $Status = "LOW SPACE" }

        [PSCustomObject]@{
            Drive       = $Disk.DeviceID
            Volume      = $Disk.VolumeName
            SizeGB      = $SizeGB
            FreeGB      = $FreeGB
            PercentFree = $PercentFree
            Status      = $Status
        }
    }

    $Report | Format-Table -AutoSize
    
    if ($Report.Status -contains "LOW SPACE") {
        Write-Host "[ALERT] One or more drives are below the $Threshold% threshold!" -ForegroundColor Red
    } else {
        Write-Host "[OK] All drives have sufficient space." -ForegroundColor Green
    }
} catch {
    Write-Host "[FAIL] Failed to get disk report for $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
}
