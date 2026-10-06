<#
.SYNOPSIS
    Retrieves SentinelOne agent details based on Hostname, IP, or Last Username.

.DESCRIPTION
    This script queries the SentinelOne API for a specific endpoint using
    one of three search terms: Hostname, IP Address, or Last Logged-in User.
    It returns a clean summary of the active agent, or raw nested JSON
    when used with the -VerboseOutput switch.

.PARAMETER Hostname
    Optional. The hostname (or partial hostname) of the agent to search for.

.PARAMETER IPAddress
    Optional. The Last Management IP address of the agent to search for.

.PARAMETER UserName
    Optional. The Last Logged-in Username to search for.

.PARAMETER ApiKey
    Optional. The API key for S1. Automatically loaded from secure storage if absent.

.PARAMETER VerboseOutput
    Optional. Switch to dump the raw JSON Agent object and Network Interfaces.

.EXAMPLE
    .\Get-S1Agent.ps1 -Hostname "MY-LAPTOP-01"
.EXAMPLE
    .\Get-S1Agent.ps1 -IPAddress "10.199.151.168"
.EXAMPLE
    .\Get-S1Agent.ps1 -UserName "robert.george"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [string]$Hostname,

    [Parameter(Mandatory=$false)]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$false)]
    [string]$UserName,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey,

    [Parameter(Mandatory=$false)]
    [Alias("V")]
    [switch]$VerboseOutput
)

# Validate at least one search parameter is provided
if (-not $Hostname -and -not $IPAddress -and -not $UserName) {
    Write-Error "You must provide at least one search parameter: -Hostname, -IPAddress, or -UserName."
    return
}

# Configuration - Auth
$S1Tenant = "usea1-017.sentinelone.net"

try {
    # Import the secure credential if ApiKey not provided
    if (-not $ApiKey) {
        $cred = Import-Clixml -Path "C:\Secure\SentinelOneCred.xml" -ErrorAction Stop
        $ApiKey = $cred.GetNetworkCredential().Password
    }

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Error "SentinelOne API Key is empty. Please recreate C:\Secure\SentinelOneCred.xml within this Admin session."
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
    # Build the dynamic query URL
    $uri = "$BaseUrl/agents?"
    if ($Hostname) {
        Write-Host "Fetching agents from SentinelOne (Hostname: $Hostname)..."
        $uri += "computerName__contains=$Hostname&"
    } elseif ($IPAddress) {
        # S1 API doesn't support direct IP search effectively, but networkInterfaceInetAddresses__contains does sometimes hit.
        # However, as proved by previous scripts, doing a full limits pull and filtering locally is much more reliable for IPs.
        Write-Host "Fetching agents from SentinelOne (IP: $IPAddress)..."
    } elseif ($UserName) {
        Write-Host "Fetching agents from SentinelOne (User: $UserName)..."
        $uri += "lastLoggedInUserName__contains=$UserName&"
    }
    
    $uri += "limit=1000"

    # Fetch agents
    $allAgents = @()
    $cursor = $null

    do {
        $pageUri = $uri
        if ($cursor) { $pageUri += "&cursor=$cursor" }
        $response = Invoke-RestMethod -Uri $pageUri -Headers $Headers -Method Get
        $batch = $response.data
        if ($batch) { $allAgents += $batch }
        $cursor = $response.pagination.nextCursor
    } while ($cursor)

    Write-Host "Successfully retrieved $($allAgents.Count) agents.`n"

    # Secondary Local Filter (required for IP addresses)
    $matchingAgents = @()
    if ($IPAddress) {
        foreach ($agent in $allAgents) {
            $mgmIp = [string]$agent.lastIpToMgmt
            if ($mgmIp.Trim() -match [regex]::Escape($IPAddress)) {
                $matchingAgents += $agent
            }
        }
    } else {
        $matchingAgents = $allAgents
    }

    # Output Results
    if ($matchingAgents -and $matchingAgents.Count -gt 0) {
        if ($IPAddress) { Write-Host "Found $($matchingAgents.Count) agent(s) matching IP '$IPAddress':`n" -ForegroundColor Green }
        else { Write-Host "Found $($matchingAgents.Count) matching agent(s):`n" -ForegroundColor Green }
        
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
        Write-Warning "No matching agents found."
    }

} catch {
    Write-Error "Failed to query SentinelOne API. $_"
}
