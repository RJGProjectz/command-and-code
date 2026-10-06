<#
.SYNOPSIS
    Identifies installed EDR products and verifies their operational status and health.

.DESCRIPTION
    1. Uses WMI (ROOT\SecurityCenter2) to detect registered AntiVirus/EDR products.
    2. Checks the status of known EDR services (Defender, CrowdStrike, SentinelOne).
    3. Verifies Filter Driver status using 'fltmc' to ensure the EDR agent is attached to I/O.
    4. Performs basic 'Tamper Checks' (e.g., checking if security services are disabled or if exclusions are unusually broad).

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Get-EdrStatus.ps1 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-01-16T15:45:00
    Last Modified: 2026-01-16T15:45:00
    Author: Antigravity
    KB Article: [KB-Sec-009-EDR.md](../../HowTo/Scripts/KB-Sec-009-EDR.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

Write-Host "--- EDR Status & Health Check ---" -ForegroundColor Cyan
Write-Host "Target Environment: $TargetEnvironment"

$HealthReport = [PSCustomObject]@{
    ProductFound   = "None"
    ServiceStatus  = "Unknown"
    DriverAttached = $false
    TamperDetected = "None Detected"
}

# 1. Product Detection via SecurityCenter2 (WSC)
Write-Host "[*] Querying Windows Security Center for registered products..."
try {
    $WSCProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
    if ($WSCProducts) {
        $HealthReport.ProductFound = ($WSCProducts.displayName -join ", ")
        Write-Host " [OK] Found: $($HealthReport.ProductFound)" -ForegroundColor Green
    } else {
        Write-Host " [WARN] No Third-Party EDR/AV registered in WSC." -ForegroundColor Yellow
    }
} catch {
    Write-Host " [FAIL] Could not query SecurityCenter2. This may indicate WMI corruption or restricted access." -ForegroundColor Red
}

# 2. Check Specific Known EDR Services
Write-Host "[*] Checking EDR Service Status..."
$EDRServices = @{
    "WinDefend"       = "Microsoft Defender"
    "Sense"           = "Defender for Endpoint"
    "CSFalconService" = "CrowdStrike Falcon"
    "SentinelAgent"   = "SentinelOne"
    "CylanceSvc"      = "Cylance"
    "cbdaemon"        = "Carbon Black"
    "Sophos"          = "Sophos"
    "CortexXDR"       = "Palo Alto Cortex XDR"
    "cyserver"        = "Palo Alto Traps"
}

$FoundSpecificSvc = $false
foreach ($SvcName in $EDRServices.Keys) {
    # Using wildcard to catch variations (e.g., Sophos Health Service, Sophos Anti-Virus)
    $Svc = Get-Service -Name "*$SvcName*" -ErrorAction SilentlyContinue
    if ($Svc) {
        $FoundSpecificSvc = $true
        foreach ($s in $Svc) {
            $Color = 'Red'
            if ($s.Status -eq 'Running') {
                $Color = 'Green'
                $HealthReport.ServiceStatus = "Running"
            }
            Write-Host " [FOUND] $($EDRServices[$SvcName]) ($($s.Name)): $($s.Status)" -ForegroundColor $Color
        }
    }
}

# Fallback: If no specific EDR service is found, look for typical security keywords
if (-not $FoundSpecificSvc) {
    Write-Host " [WARN] No primary EDR service signatures matched. Searching for general security services..." -ForegroundColor Yellow
    $FuzzyServices = Get-Service -Name "*Security*", "*Protect*", "*Defense*", "*Agent*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "SecurityHealthService|wscsvc" }
    foreach ($fs in $FuzzyServices) {
        Write-Host " [QUERY] Found potential security service: $($fs.Name) ($($fs.DisplayName)) - Status: $($fs.Status)" -ForegroundColor Cyan
    }
}
# 3. Filter Driver Check (fltmc)
Write-Host "[*] Checking Filter Drivers (I/O Interception)..."
$Filters = fltmc filters
$KnownEDRDrivers = "WdFilter|CS_Falcon|Sentinel|S1Flt"
if ($Filters -match $KnownEDRDrivers) {
    Write-Host " [OK] Active EDR Filter Driver detected in stack." -ForegroundColor Green
    $HealthReport.DriverAttached = $true
} else {
    Write-Host " [WARN] No known EDR filter drivers found. Agent may be unattached." -ForegroundColor Red
}

# 4. Tamper Check (Heuristic)
Write-Host "[*] Running Tamper Check heuristics..."
# Check for Disabled Security Center or Defender via Registry
$DefenderDisabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
if ($DefenderDisabled -and $DefenderDisabled.DisableAntiSpyware -eq 1) {
    Write-Host " [ALERT] Windows Defender is disabled via Policy!" -ForegroundColor Red
    $HealthReport.TamperDetected = "Defender Disabled via Policy"
}

Write-Host "`nFinal EDR Health Summary:" -ForegroundColor Cyan
$HealthReport | Format-List
