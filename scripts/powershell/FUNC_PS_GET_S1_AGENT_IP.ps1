<#
.SYNOPSIS
    Retrieves SentinelOne agent details based on local IP address.

.DESCRIPTION
    This script queries the SentinelOne API to find an agent matching
    a specific local IP address. It is intended to be called by profile
    wrapper functions for quick access.

.PARAMETER IPAddress
    Mandatory. The IP address of the agent to search for.

.EXAMPLE
    .\Get-S1AgentIP.ps1 -IPAddress "10.0.0.50"
    
.NOTES
    Security Domain: Endpoint
    Author: Antigravity
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$IPAddress,

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
        Write-Error "SentinelOne API Key is empty. This happens if the credential XML was created by a different user context (like your standard user) and you are now running as Administrator (due to DPAPI encryption). Please recreate C:\Secure\SentinelOneCred.xml within this Admin session."
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

# Fetch all agents (handling pagination)
$allAgents = @()
$limit = 1000
$cursor = $null

try {
    Write-Host "Fetching agents from SentinelOne (this may take a moment)..."
    do {
        $uri = "$BaseUrl/agents?limit=$limit"
        if ($cursor) { $uri += "&cursor=$cursor" }

        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
        $batch = $response.data

        if ($batch) {
            $allAgents += $batch
        }

        $cursor = $response.pagination.nextCursor

    } while ($cursor)

    Write-Host "Successfully retrieved $($allAgents.Count) total agents.`n"

    # Filter for the specific IP address locally using an explicit loop and type casting
    $matchingAgents = @()
    foreach ($agent in $allAgents) {
        $mgmIp = [string]$agent.lastIpToMgmt
        if ($mgmIp.Trim() -match [regex]::Escape($IPAddress)) {
            $matchingAgents += $agent
        }
    }

    if ($matchingAgents -and $matchingAgents.Count -gt 0) {
        Write-Host "Found $($matchingAgents.Count) agent(s) matching IP '$IPAddress':`n" -ForegroundColor Green
        
        foreach ($agent in $matchingAgents) {
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
        Write-Warning "No agents found matching IP address '$IPAddress'."
    }
} catch {
    Write-Error "Failed to query SentinelOne API. $_"
}
