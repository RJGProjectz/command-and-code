<#
.SYNOPSIS
    SentinelOne Reboot Script - Broadcast + Delayed Reboot.

.DESCRIPTION
    Pulls actionable agents from SentinelOne API and coordinates a staggered reboot
    process with user notification.

.PARAMETER TargetEnvironment
    Mandatory. Set to 'Test' or 'Prod'.

.EXAMPLE
    .\S1Maintenance.ps1 -TargetEnvironment Test
    
.NOTES
    Security Domain: Endpoint
    Author: Antigravity
    Created: 2026-02-04T15:45:00
    Last Modified: 2026-02-04T15:45:00
    KB Article: [README](./README.md)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$false)]
    [string]$ApiKey
)

# ==========================
# CONFIGURATION - Auth
# ==========================
$S1Tenant = "usea1-017.sentinelone.net"

# Import the secure credential if ApiKey not provided
if (-not $ApiKey) {
    $cred = Import-Clixml -Path "C:\Secure\SentinelOneCred.xml"
    $ApiKey = $cred.GetNetworkCredential().Password
}

$BaseUrl = "https://$S1Tenant/web/api/v2.1"
$Headers = @{
    "Authorization" = "ApiToken $apiKey"
    "Content-Type"  = "application/json"
}

# ==========================
# SCOPE - Sites & Groups
# ==========================
$GroupId = ""  # leave blank "" to ignore - Windows 10 - Event Log Test Group - 1925656738877123659

# ==========================
# ACTIONS & Testing
# ==========================
# RunMode Options: 
# "DryRun" - Console output only, no emails.
# "Report" - Sends email report.
$RunMode = "Report"

$IgnoreActions = $False   # Set $true to report all agents regardless of userActionsNeeded
$actions = @("reboot_needed", "extended_exclusions_partially_accepted")

# ==========================
# --- Email ---
# ==========================
$SmtpServer = "10.99.51.203"
$MailFrom   = "robert.george@servus.ca"
$MailTo     = "robert.george@servus.ca"
$MailSubjectPrefix = "SentinelOne Devices Requiring Action"

# ==========================
# LOGGING
# ==========================
$logDir = "C:\S1Automation\"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force }
$logFile = "C:\S1Automation\S1Reboot_$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss')).log"

Start-Transcript -Path $logFile 

Write-Host "`n=== SentinelOne $RunMode Script Started ===`n"

# ==========================
# FUNCTIONS
# ==========================

function Get-S1Agents {
    $allAgents = @()
    $limit = 1000
    $cursor = $null

    do {
        $uri = "$BaseUrl/agents?limit=$limit"
        if ($cursor) { $uri += "&cursor=$cursor" }
        if ($GroupId) { $uri += "&groupIds=$GroupId" }

        $response = Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get
        $batch = $response.data

        if ($batch) {
            $allAgents += $batch
            Write-Host "Retrieved $($batch.Count) agents (Total: $($allAgents.Count))"
        }

        $cursor = $response.pagination.nextCursor

    } while ($cursor)

    return $allAgents
}

function Get-ActionableAgents {
    param ($agents)

    if ($IgnoreActions) {
        Write-Host "Ignoring actions filter. All pulled agents will be targeted."
        return $agents
    }

    return $agents | Where-Object {
        $null -ne $_.userActionsNeeded -and
        ($_.userActionsNeeded | Where-Object { $_ -in $actions }).Count -gt 0
    }
}

function Send-ReportEmail {
    param ($actionableAgents)

    if ($actionableAgents.Count -eq 0) {
        $body = "<p>No devices currently require action.</p>"
        $subject = "$MailSubjectPrefix - None"
    }
    else {
        $preContent = "<h2>Devices Requiring Reboots</h2><p>Generated: $(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')</p>"

        $body = ($actionableAgents | Select-Object `
    computerName, isActive, domain, machineType, osName, 
    lastIpToMgmt, lastActiveDate, uuid|
    ConvertTo-Html `
        -Title "SentinelOne Action Required Report" `
        -PreContent $preContent) -join "`r`n"
        $subject = "$MailSubjectPrefix - $($actionableAgents.Count) Devices"
    }

    Send-MailMessage `
        -From $MailFrom `
        -To $MailTo `
        -Subject $subject `
        -Body $body `
        -BodyAsHtml `
        -SmtpServer $SmtpServer

    Write-Host "Report email sent to $MailTo"
}



# ==========================
# PULL AGENTS
# ==========================
$agents = Get-S1Agents
Write-Host "Pulled $($agents.Count) agents"

# ==========================
# FILTER ACTIONABLE AGENTS
# ==========================
$actionableAgents = Get-ActionableAgents -agents $agents

Write-Host "`nTotal actionable agents: $($actionableAgents.Count)`n"

$actionableAgents | Select-Object computerName, isActive, domain, machineType, osName, 
    lastIpToMgmt, lastActiveDate, uuid |
    Format-Table -AutoSize

# ==========================
# PERFORM REPORT
# ==========================
if ($RunMode -eq "Report") {
    Write-Host "Report mode enabled."
    Send-ReportEmail -actionableAgents $actionableAgents
}
else {
    Write-Host "Dry-Run mode: Report NOT sent."
}

Write-Host "`n=== SentinelOne $RunMode Script Finished ===`n"
Stop-Transcript
