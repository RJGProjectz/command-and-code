<#
.SYNOPSIS
    Secure script launcher with mandatory integrity verification.
    
.DESCRIPTION
    Verifies script integrity using Verify-ScriptIntegrity.ps1 before 
    execution. Prevents unauthorized or modified scripts from running.

.PARAMETER Path
    Path to the script to execute.

.PARAMETER Arguments
    Additional arguments to pass to the script.

.EXAMPLE
    .\Invoke-Secure.ps1 -Path "Scripts\Security\Get-LinuxPosture.sh" -Arguments "--env Test"
.NOTES
    Security Domain: Operations
    Author: Antigravity
    Created: 2026-02-04T11:15:00
    Last Modified: 2026-02-06T10:10:00
    Documentation: [PowerShell Defensive Scripting](../../docs/languages/powershell/defensive-scripting.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$true)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [string]$Arguments = ""
)

$Verifier = Join-Path $PSScriptRoot "FUNC_PS_VERIFY_SCRIPT_INTEGRITY.ps1"

if ($TargetEnvironment -eq "Test") {
    Write-Host "[TEST] Would verify integrity of $Path against the manifest, then execute it with: $Arguments" -ForegroundColor Yellow
    return
}

# 1. Verify Integrity
Write-Host "[*] Pre-Execution Integrity Check..." -ForegroundColor Gray
# Run the verifier in-process so this works under pwsh on any OS (it returns $true/$false)
$IntegrityOk = (& $Verifier -Path $Path -ErrorAction SilentlyContinue) -eq $true

if ($IntegrityOk) {
    Write-Host "[OK] Integrity Verified. Proceeding to execution." -ForegroundColor Green
} else {
    Write-Error "INTEGRITY CHECK FAILED. Execution aborted for security reasons."
    return
}

# 2. Execute based on extension
$Extension = [System.IO.Path]::GetExtension($Path)

Write-Host "[*] Executing: $Path`n" -ForegroundColor Cyan

if ($Extension -eq ".ps1") {
    powershell -ExecutionPolicy Bypass -File $Path $Arguments
}
elseif ($Extension -eq ".sh" -or $Extension -eq ".bash") {
    # Assuming Bash is available (WSL, Git Bash, or Linux host)
    bash $Path $Arguments
}
else {
    Write-Error "Unsupported script type: $Extension"
}
