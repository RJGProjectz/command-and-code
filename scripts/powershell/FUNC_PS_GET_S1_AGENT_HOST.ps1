<#
.SYNOPSIS
    Retrieves SentinelOne agent details based on Hostname for debugging.

.DESCRIPTION
    This script queries the SentinelOne API for a specific computerName
    and dumps the networking properties. This is used to understand the 
    data structure returned to fix IP filtering.

.PARAMETER Hostname
    Mandatory. The hostname of the agent to search for.

.PARAMETER ApiKey
    Optional. The API key for S1.

.EXAMPLE
    .\Get-S1AgentHost.ps1 -Hostname "MY-LAPTOP-01"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Hostname,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey,

    [Parameter(Mandatory=$false)]
    [Alias("V")]
    [switch]$VerboseOutput
)

# Configuration - Auth
$S1Tenant = "usea1-017.sentinelone.net"

try {
    # Import the secure credential if ApiKey not provided
    if (-not $ApiKey) {
        $cred = Import-Clixml -Path "C:\Secure\SentinelOneCred.xml" -ErrorAction Stop
        $ApiKey = $cred.GetNetworkCredential().Password
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Error "SentinelOne API Key is empty."
        return
    }
} catch {
    Write-Error "Failed to load SentinelOne API key from C:\Secure\SentinelOneCred.xml. Ensure the file exists, and you have access: $_"
    return
}

$BaseUrl = "https://$S1Tenant/web/api/v2.1"
$Headers = @{
    "Authorization" = "ApiToken $ApiKey"
    "Content-Type"  = "application/json"
}

try {
    Write-Host "Fetching agents from SentinelOne (computerName__contains=$Hostname)..."
    $uri = "$BaseUrl/agents?computerName__contains=$Hostname&limit=10"

    $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
    $agents = $response.data

    if ($agents -and $agents.Count -gt 0) {
        Write-Host "Successfully retrieved $($agents.Count) agents matching '$Hostname'.`n"
        
        foreach ($agent in $agents) {
            Write-Host "=============================================" -ForegroundColor Cyan
            Write-Host "Hostname:    $($agent.computerName)" -ForegroundColor Cyan
            Write-Host "Domain:      $($agent.domain)" -ForegroundColor Cyan
            Write-Host "Active:      $($agent.isActive)" -ForegroundColor Cyan
            Write-Host "MachineType: $($agent.machineType)" -ForegroundColor Cyan
            Write-Host "OS Name:     $($agent.osName)" -ForegroundColor Cyan
            Write-Host "Last Active: $($agent.lastActiveDate)" -ForegroundColor Cyan
            Write-Host "Last User:   $($agent.lastLoggedInUserName)" -ForegroundColor Cyan
            Write-Host "LastIPToMgt: $($agent.lastIpToMgmt)" -ForegroundColor Cyan
            if ($VerboseOutput) {
                Write-Host "Network Interfaces Output:" -ForegroundColor Yellow
                $agent.networkInterfaces | Format-List
                Write-Host "=============================================" -ForegroundColor Cyan
                Write-Host "Raw Agent Object dump:" -ForegroundColor Yellow
                $agent | ConvertTo-Json -Depth 3
            }
        }

    } else {
        Write-Warning "No agents found matching hostname '$Hostname'."
    }
} catch {
    Write-Error "Failed to query SentinelOne API. $_"
}
