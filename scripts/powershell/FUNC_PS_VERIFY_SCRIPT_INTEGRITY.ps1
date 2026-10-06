<#
.SYNOPSIS
    Verifies the integrity of a script against the repository manifest.
    
.DESCRIPTION
    Calculates the SHA-256 hash of a target file and compares it to the
    known-good hash stored in Audit/integrity_manifest.json.

.PARAMETER Path
    Path to the script file to verify.

.EXAMPLE
    .\Verify-ScriptIntegrity.ps1 -Path "Scripts\Security\Get-LinuxPosture.sh"
.NOTES
    Security Domain: Operations
    Author: Antigravity
    Created: 2026-02-04T09:30:00
    Last Modified: 2026-02-04T15:10:00
    KB Article: [KB-Fund-042](../../Fundamentals/KB-Fund-042-OS-Security-Script-Integrity.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$true)]
    [string]$Path
)

$ManifestPath = Join-Path $PSScriptRoot "../../Audit/integrity_manifest.json"

if (-not (Test-Path $Path)) {
    Write-Error "Target file not found: $Path"
    return $false
}

if (-not (Test-Path $ManifestPath)) {
    Write-Warning "Integrity manifest not found at $ManifestPath. Cannot verify."
    return $null
}

try {
    $Manifest = Get-Content $ManifestPath | ConvertFrom-Json
    $RelativePath = Resolve-Path $Path -Relative
    
    # Normalize path separators for cross-platform manifest support
    $NormalizedPath = $RelativePath.Replace('\', '/')
    if ($NormalizedPath.StartsWith("./")) { $NormalizedPath = $NormalizedPath.Substring(2) }

    $FileHash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
    $StoredEntry = $Manifest | Where-Object { $_.Path -eq $NormalizedPath }

    if ($null -eq $StoredEntry) {
        Write-Warning "No integrity record found for: $NormalizedPath"
        return $false
    }

    if ($FileHash -eq $StoredEntry.Hash) {
        Write-Host "[OK] Integrity verified for $NormalizedPath" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[CRITICAL] Hash mismatch for $NormalizedPath!" -ForegroundColor Red
        Write-Host "Expected: $($StoredEntry.Hash)"
        Write-Host "Actual:   $FileHash"
        return $false
    }
} catch {
    Write-Error "Failed to process integrity check: $($_.Exception.Message)"
    return $false
}
