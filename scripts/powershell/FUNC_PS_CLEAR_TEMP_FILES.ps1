<#
.SYNOPSIS
    Cleans up temporary files on a local or remote computer.

.DESCRIPTION
    1. Targets C:\Windows\Temp and User Temp folders.
    2. Removes files older than X days.
    3. Handles locked files gracefully.

.PARAMETER ComputerName
    The name of the computer. Defaults to localhost.

.PARAMETER Days
    Keep files newer than this many days. Defaults to 7.

.PARAMETER TargetEnvironment
    'Test' (default) simulates. 'Prod' executes.

.EXAMPLE
    .\Clear-TempFiles.ps1 -ComputerName "Server01" -Days 14 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-01-16T16:20:00
    Last Modified: 2026-01-16T16:20:00
    Author: Antigravity
    Documentation: [Safe Temporary File Purging](../../docs/tasks/administration/temp-file-cleanup.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = "localhost",

    [Parameter(Mandatory=$false)]
    [int]$Days = 7,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test"
)

Write-Host "--- Remote Temp Cleanup ---" -ForegroundColor Cyan
Write-Host "Target: $ComputerName (Older than $Days days)"

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would delete temp files older than $Days days on $ComputerName" -ForegroundColor Yellow
    return
}

$ScriptBlock = {
    param($Days)
    $TargetFolders = @("C:\Windows\Temp", "$env:TEMP")
    $LimitDate = (Get-Date).AddDays(-$Days)
    
    foreach ($Folder in $TargetFolders) {
        if (Test-Path $Folder) {
            Write-Output "Processing $Folder..."
            Get-ChildItem -Path $Folder -Recurse -File | Where-Object { $_.LastWriteTime -lt $LimitDate } | ForEach-Object {
                try {
                    Remove-Item $_.FullName -Force -ErrorAction Stop
                    Write-Output " Deleted: $($_.Name)"
                } catch {
                    # Skip locked files
                    Write-Verbose "Skipped (locked): $($_.TargetObject)"
                }
            }
        }
    }
}

try {
    if ($ComputerName -eq "localhost") {
        Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $Days
    } else {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $Days -ErrorAction Stop
    }
    Write-Host "[OK] Temp cleanup complete on $ComputerName." -ForegroundColor Green
} catch {
    Write-Host "[FAIL] Failed to run temp cleanup on $ComputerName. Error: $($_.Exception.Message)" -ForegroundColor Red
}
