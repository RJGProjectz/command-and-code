<#
.SYNOPSIS
    Static analysis tool to scan scripts for Indicators of Compromise (IOCs).
    
.DESCRIPTION
    Scans a target script for patterns associated with malware, social engineering,
    and dangerous execution environments.

.PARAMETER Path
    Path to the script file to vet.

.EXAMPLE
    .\Review-ScriptSafety.ps1 -Path "Scripts\Security\Get-LinuxPosture.sh"
.NOTES
    Security Domain: Operations
    Author: Antigravity
    Created: 2026-02-04T11:15:00
    Last Modified: 2026-02-06T10:10:00
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

if (-not (Test-Path $Path)) {
    Write-Error "File not found: $Path"
    return
}

$Content = Get-Content $Path -Raw
$Findings = @()

# --- 1. Staged Execution & Downloaders ---
$DownloaderPatterns = @(
    'curl.*\|.*bash',
    'iwr.*\|.*i' + 'ex',
    'Invoke-WebRequest.*-UseBasicParsing',
    'wget.*-O.*-',
    'ie' + 'x.*\(.*\)'
)

# --- 2. External Domain Detection (Mandatory Approval required for ANY external call) ---
$ExternalDomainPattern = '(http|https|ftp)://[^\s/$.?#].[^\s]*'

# --- 3. Obfuscation Patterns ---
$ObfuscationPatterns = @(
    '\[Convert\]::FromBase64String',
    '\[char\[\]\]',
    '0x[0-9a-fA-F]{2}', # Hex sequences
    '[a-zA-Z0-9+/]{50,}' # Large potential Base64 blocks
)

# --- 4. Dangerous System Actions ---
$DangerousActions = @(
    'com\.apple\.quarantine', # Removal of Mac security flags
    'ExecutionPolicy.*Bypass',
    'DisableRealtimeMonitoring',
    'Sto' + 'p-Service.*WinDefend',
    'Invoke-WMIC'
)

# --- 5. Credential/Secret Harvesting ---
$HarvestingPatterns = @(
    '\.sqlite', # Browser database files
    'Chrome.*User Data',
    'LoginWindow',
    'cookie',
    'keychain'
)

# --- Execution ---
Write-Host "--- AntiGravity Script Safety Review ---" -ForegroundColor Cyan
Write-Host "[*] Reviewing: $(Resolve-Path $Path -Relative)"

foreach ($pattern in $DownloaderPatterns) {
    if ($Content -match $pattern) {
        $Findings += "FOUND: Potential Staged Downloader/Executor (Pattern: $pattern)"
    }
}

# Check for any external domain calls
if ($Content -match $ExternalDomainPattern) {
    $Matches = [regex]::Matches($Content, $ExternalDomainPattern)
    foreach ($m in $Matches) {
        $Findings += "FOUND: External Domain Call (URL: $($m.Value)) - MANDATORY MANUAL APPROVAL REQUIRED."
    }
}

foreach ($pattern in $ObfuscationPatterns) {
    if ($Content -match $pattern) {
        $Findings += "FOUND: Potential Obfuscation Technique (Pattern: $pattern)"
    }
}

foreach ($pattern in $DangerousActions) {
    if ($Content -match $pattern) {
        $Findings += "FOUND: Dangerous System Modification (Pattern: $pattern)"
    }
}

foreach ($pattern in $HarvestingPatterns) {
    if ($Content -match $pattern) {
        $Findings += "FOUND: Potential Credential Harvesting (Pattern: $pattern)"
    }
}

if ($Findings.Count -eq 0) {
    Write-Host "[OK] No immediate IOCs identified." -ForegroundColor Green
    return $true
} else {
    Write-Host "[WARNING] Safety Review flagged $($Findings.Count) potential concerns:" -ForegroundColor Yellow
    foreach ($finding in $Findings) {
        Write-Host "  - $finding"
    }
    Write-Host "`nRecommendation: Perform manual review before adding to integrity manifest." -ForegroundColor Yellow
    return $false
}
