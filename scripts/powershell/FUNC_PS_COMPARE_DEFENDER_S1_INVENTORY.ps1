<#
.SYNOPSIS
    Identifies Windows 10/11 devices in Microsoft Defender for Endpoint missing the SentinelOne agent.

.DESCRIPTION
    This script queries the Microsoft Graph Security API for Defender machines and the SentinelOne Management API for agents.
    It correlates the two datasets using Serial Number and Hostname to find devices present in MDE but missing from S1.

.PARAMETER TargetEnvironment
    Mandatory. Target environment for the operation (Test, Prod).

.PARAMETER DefenderTenantId
    The Azure AD Tenant ID for Microsoft Graph authentication.

.PARAMETER DefenderClientId
    The Client ID (App ID) with SecurityActions.Read.All or Machine.Read.All permissions.

.PARAMETER DefenderClientSecret
    The Client Secret for the App Registration.

.PARAMETER S1Url
    The base URL for the SentinelOne management console (e.g., https://your-console.sentinelone.net).

.PARAMETER S1Token
    The API Token for SentinelOne authentication.

.EXAMPLE
    .\Compare-DefenderS1Inventory.ps1 -TargetEnvironment Test -DefenderTenantId "..." -DefenderClientId "..." -S1Url "..." -S1Token "..."

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-19T09:20:00
    Last Modified: 2026-01-19T09:20:00
    KB Article: [KB-Sec-017-InventoryGap.md](../../HowTo/Scripts/KB-Sec-017-InventoryGap.md)
#>

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    $TargetEnvironment,

    [Parameter(Mandatory=$true)]
    [string]$DefenderTenantId,

    [Parameter(Mandatory=$true)]
    [string]$DefenderClientId,

    [Parameter(Mandatory=$true)]
    [Alias("DefenderSecret")]
    [string]$DefenderClientSecret,

    [Parameter(Mandatory=$true)]
    [string]$S1Url,

    [Parameter(Mandatory=$true)]
    [string]$Token
)

# 1. Authenticate to Microsoft Graph
Write-Host "[*] Authenticating to Microsoft Graph..." -ForegroundColor Cyan
$TokenBody = @{
    grant_type    = "client_credentials"
    scope         = "https://graph.microsoft.com/.default"
    client_id     = $DefenderClientId
    client_secret = $DefenderClientSecret
}
$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$DefenderTenantId/oauth2/v2.0/token" -Method Post -Body $TokenBody
$GraphHeader = @{ Authorization = "Bearer $($TokenResponse.access_token)" }

# 2. Fetch Defender Devices
Write-Host "[*] Fetching Defender device inventory..." -ForegroundColor Cyan
$DefenderMachines = $null
try {
    # Note: Using the security/microsoft.graph.defender endpoint if available, else standard machines
    $DefUri = "https://graph.microsoft.com/v1.0/security/microsoft.graph.defender/machines"
    $DefResponse = Invoke-RestMethod -Uri $DefUri -Headers $GraphHeader -Method Get
    $DefenderMachines = $DefResponse.value | Where-Object { $_.osPlatform -match "Windows 10|Windows 11" }
} catch {
    Write-Warning "Failed to fetch from Defender API: $($_.Exception.Message)"
    return
}

# 3. Fetch SentinelOne Devices
Write-Host "[*] Fetching SentinelOne agent inventory..." -ForegroundColor Cyan
$S1Header = @{ Authorization = "ApiToken $Token"; "Content-Type" = "application/json" }
$S1Agents = $null
try {
    $S1Uri = "$S1Url/web/api/v2.1/agents?osTypes=windows"
    $S1Response = Invoke-RestMethod -Uri $S1Uri -Headers $S1Header -Method Get
    $S1Agents = $S1Response.data
} catch {
    Write-Warning "Failed to fetch from SentinelOne API: $($_.Exception.Message)"
    return
}

# 4. Correlation and Gap Analysis
Write-Host "[*] Correlating inventories..." -ForegroundColor Cyan
$Gaps = @()

foreach ($Machine in $DefenderMachines) {
    # Match by Serial Number (Preferred)
    $Match = $S1Agents | Where-Object { $_.serialNumber -eq $Machine.serialNumber -and $Machine.serialNumber }
    
    # Fallback to Hostname
    if (-not $Match) {
        $Match = $S1Agents | Where-Object { $_.computerName -eq $Machine.computerName }
    }

    if (-not $Match) {
        $Gaps += [PSCustomObject]@{
            ComputerName = $Machine.computerName
            OS           = $Machine.osPlatform
            SerialNumber = $Machine.serialNumber
            LastSeen     = $Machine.lastSeenDateTime
            Status       = "Missing S1 Agent"
        }
    }
}

# 5. Output Results
Write-Host "[!] Found $($Gaps.Count) devices in Defender missing SentinelOne." -ForegroundColor Yellow
$Gaps | Out-GridView -Title "Defender vs S1 Inventory Gaps ($TargetEnvironment)" -Wait:$false
$Gaps | Export-Csv -Path "$PSScriptRoot\InventoryGaps_$($TargetEnvironment).csv" -NoTypeInformation

Write-Host "[+] Audit complete. Report saved to: $PSScriptRoot\InventoryGaps_$($TargetEnvironment).csv" -ForegroundColor Green
