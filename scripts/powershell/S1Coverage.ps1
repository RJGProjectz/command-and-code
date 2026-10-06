<#
.SYNOPSIS
    Automated SentinelOne EDR coverage validation and remediation framework.

.DESCRIPTION
    This script interacts with the SentinelOne REST API to pull agent inventory, 
    evaluates EDR coverage compliance against established baseline requirements,
    generates local structured reports, optionally sends SMTP summaries, and 
    can autonomously perform defined remediation actions on non-compliant endpoints.

.PARAMETER Mode
    Specifies the runtime mode and capabilities enabled for this execution:
    - LocalOnly: API queries, evaluate compliance, generate local reports.
    - ReportAndEmail: LocalOnly + SMTP email.
    - AllActions: ReportAndEmail + Automated remediation execution.

.EXAMPLE
    .\S1Coverage.ps1 -Mode LocalOnly
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('LocalOnly','ReportAndEmail','AllActions')]
    [string]$Mode,

    [Parameter(Mandatory=$false)]
    [string]$TestGroupId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================
# 1. Configuration & Constants
# ==========================================
$Config = @{
    # API & Compliance Requirements
    S1Url                 = "https://usea1-yourconsole.sentinelone.net"
    ApprovedVersion       = "23.2.3.358"
    MaxDaysOffline        = 7
    
    # Directory Structure
    BaseDir               = "C:\ForgePoint\EDR"
    
    # SMTP Settings
    SmtpServer            = "smtp.forgepoint.internal"
    SmtpFrom              = "edr-automation@forgepoint.com"
    SmtpTo                = "soc@forgepoint.com"
}

# Ensure Core Directories Exist
$LogDir     = Join-Path $Config.BaseDir "Logs"
$ReportDir  = Join-Path $Config.BaseDir "Reports" 
$ArchiveDir = Join-Path $Config.BaseDir "Archive"

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $ReportDir)) { New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $ArchiveDir)) { New-Item -Path $ArchiveDir -ItemType Directory -Force | Out-Null }

$LogFile = Join-Path $LogDir "S1_Coverage_$(Get-Date -Format 'yyyyMM').log"

# ==========================================
# 2. Core Functions
# ==========================================

Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][ValidateSet('INFO','WARN','ERROR','REMEDIATION')][string]$Level = 'INFO'
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

Function Get-SecurityToken {
    <#
    .DESCRIPTION
        Retrieves the API token from AES-encrypted SecureString file.
        To generate: Read-Host -AsSecureString | ConvertFrom-SecureString | Out-File C:\ForgePoint\EDR\s1_token.secure
    #>
    $CredPath = Join-Path $Config.BaseDir "s1_token.secure"
    if (Test-Path $CredPath) {
        Write-Log "Retrieving S1 API token securely."
        $SecureToken = Get-Content $CredPath | ConvertTo-SecureString
        $BSTR  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
        $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $Token
    } else {
        Write-Log "API token file not found at $CredPath." 'ERROR'
        throw "Authentication artifact missing. Halting execution."
    }
}

Function Get-S1Agents {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$Token,
        [Parameter(Mandatory=$false)][string]$GroupId
    )
    
    $Headers = @{
        "Authorization" = "ApiToken $Token"
        "Content-Type"  = "application/json"
    }
    
    $Agents  = @()
    $Cursor  = $null
    $HasMore = $true

    Write-Log "Initiating connection to SentinelOne API (v2.1)..."
    
    try {
        while ($HasMore) {
            # Limiting to 1000 per request for enterprise efficiency
            $Uri = "$($Config.S1Url)/web/api/v2.1/agents?limit=1000"
            if ($GroupId) { $Uri += "&groupIds=$GroupId" }
            if ($Cursor) { $Uri += "&cursor=$Cursor" }

            $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -TimeoutSec 120
            
            if ($Response.data) {
                $Agents += $Response.data
            }
            
            if ($Response.pagination.nextCursor) {
                $Cursor = $Response.pagination.nextCursor
                Write-Log "Pagination cursor detected. Batched $($Agents.Count) agents..."
            } else {
                $HasMore = $false
            }
        }
        Write-Log "Successfully extracted $($Agents.Count) total endpoints."
        return $Agents
    } catch {
        Write-Log "SentinelOne API invocation failed: $_" 'ERROR'
        throw
    }
}

Function Get-S1RangerDevices {
    [CmdletBinding()]
    Param([string]$Token)
    
    $Headers = @{
        "Authorization" = "ApiToken $Token"
        "Content-Type"  = "application/json"
    }
    
    $RangerDevices = @()
    $Cursor = $null
    $HasMore = $true

    Write-Log "Initiating connection to SentinelOne Ranger API..."
    
    try {
        while ($HasMore) {
            $Uri = "$($Config.S1Url)/web/api/v2.1/ranger/devices?limit=1000"
            if ($Cursor) { $Uri += "&cursor=$Cursor" }

            $Response = Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -TimeoutSec 120
            
            if ($Response.data) {
                $RangerDevices += $Response.data
            }
            
            if ($Response.pagination.nextCursor) {
                $Cursor = $Response.pagination.nextCursor
                Write-Log "Ranger cursor detected. Batched $($RangerDevices.Count) devices..."
            } else {
                $HasMore = $false
            }
        }
        Write-Log "Successfully extracted $($RangerDevices.Count) Ranger topology endpoints."
        return $RangerDevices
    } catch {
        Write-Log "SentinelOne Ranger API invocation failed: $_" 'WARN'
        return @() # Return empty if Ranger fails/unlicensed to not break main script
    }
}

Function Test-EDRCompliance {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][array]$Agents,
        [Parameter(Mandatory=$false)][array]$RangerDevices
    )
    
    Write-Log "Evaluating EDR coverage compliance schemas (Ranger Enhanced)..."
    $Results = @()
    $Now = (Get-Date).ToUniversalTime()
    
    foreach ($Agent in $Agents) {
        $Reasons = @()
        
        # Rule 1: Last active within 24 hours
        $LastActive = [datetime]$Agent.lastActiveDate
        $DaysOffline = ($Now - $LastActive).TotalDays
        if ($DaysOffline -gt 1) {
            $BrokenAgent = $false
            if ($RangerDevices) {
                $RangerMatch = $RangerDevices | Where-Object { $_.deviceName -eq $Agent.computerName -or $_.hostname -eq $Agent.computerName } | Select-Object -First 1
                if ($RangerMatch) {
                    $RangerOffline = ($Now - [datetime]$RangerMatch.lastActiveDate).TotalDays
                    if ($RangerOffline -le 1) {
                        $Reasons += "S1 Agent Broken"
                        $BrokenAgent = $true
                    }
                }
            }
            
            if (-not $BrokenAgent) {
                $Reasons += "Offline > 24h"
            }
        }
        
        # Rule 2: Version Validation
        if ([version]$Agent.agentVersion -lt [version]$Config.ApprovedVersion) {
            $Reasons += "Outdated Version"
        }
        
        # Rule 3: Health State
        if ($Agent.isHealthy -eq $false -or $Agent.infected -eq $true) {
            $Reasons += "Unhealthy/Infected"
        }
        
        # Rule 4: Protection Mode Validations 
        if ($Agent.mitigationMode -ne 'protect') {
            $Reasons += "Detect Only Mode"
        }
        
        $IsCompliant = ($Reasons.Count -eq 0)
        
        $Results += [PSCustomObject]@{
            Hostname            = $Agent.computerName
            Id                  = $Agent.id
            OS                  = $Agent.osName
            AgentVersion        = $Agent.agentVersion
            LastActiveDate      = $Agent.lastActiveDate
            DaysOffline         = [math]::Round($DaysOffline, 1)
            IsHealthy           = $Agent.isHealthy
            MitigationMode      = $Agent.mitigationMode
            GroupId             = $Agent.groupId
            Compliant           = $IsCompliant
            NonCompliantReasons = $Reasons -join "; "
        }
    }
    
    return $Results
}

Function Invoke-Remediation {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)][array]$NonCompliantAgents, 
        [Parameter(Mandatory=$true)][string]$Token,
        [Parameter(Mandatory=$false)][array]$RangerDevices
    )
    
    $Headers = @{
        "Authorization" = "ApiToken $Token"
        "Content-Type"  = "application/json"
    }
    
    Write-Log "Initializing automated remediation protocols..." 'REMEDIATION'
    
    foreach ($Agent in $NonCompliantAgents) {
        # Circuit Breaker: Do not attempt remediation on devices offline > 7 days
        if ($Agent.DaysOffline -gt $Config.MaxDaysOffline) {
            Write-Log "Circuit Breaker: Skipping $($Agent.Hostname) (Offline for $($Agent.DaysOffline) days). Limit is $($Config.MaxDaysOffline)." 'WARN'
            continue
        }
        
        $Reasons = $Agent.NonCompliantReasons -split "; "
        
        try {
            if ($Reasons -contains "S1 Agent Broken") {
                Write-Log "Attempting native S1 Ranger remote deployment for broken agent $($Agent.Hostname)..." 'REMEDIATION'
                $RgtDevice = $null
                if ($RangerDevices) { $RgtDevice = $RangerDevices | Where-Object { $_.deviceName -eq $Agent.Hostname -or $_.hostname -eq $Agent.Hostname } | Select-Object -First 1 }
                
                if ($RgtDevice.id) {
                    $Body = @{ filter = @{ ids = @($RgtDevice.id) } } | ConvertTo-Json -Depth 5
                    Invoke-RestMethod -Uri "$($Config.S1Url)/web/api/v2.1/ranger/actions/deploy" -Headers $Headers -Method Post -Body $Body -ErrorAction Stop | Out-Null
                } else {
                    Write-Log "Failed to find native Ranger ID to deploy to $($Agent.Hostname)" 'ERROR'
                }
            }
            
            if ($Reasons -contains "Outdated Version") {
                Write-Log "Triggering agent upgrade to $($Config.ApprovedVersion) on $($Agent.Hostname)..." 'REMEDIATION'
                $Body = @{ filter = @{ ids = @($Agent.Id) }; data = @{ version = $Config.ApprovedVersion } } | ConvertTo-Json -Depth 5
                Invoke-RestMethod -Uri "$($Config.S1Url)/web/api/v2.1/agents/actions/update-software" -Headers $Headers -Method Post -Body $Body -ErrorAction Stop | Out-Null
            }
            
            if ($Reasons -contains "Detect Only Mode") {
                Write-Log "Enforcing Protection Mode on $($Agent.Hostname)..." 'REMEDIATION'
                $Body = @{ filter = @{ ids = @($Agent.Id) }; data = @{ mitigationMode = "protect" } } | ConvertTo-Json -Depth 5
                # Note: S1 policy usually overrides this unless policy is adjusted, but API permits direct override in some states
                Invoke-RestMethod -Uri "$($Config.S1Url)/web/api/v2.1/agents/actions/mitigation-mode" -Headers $Headers -Method Post -Body $Body -ErrorAction Stop | Out-Null
            }
        } catch {
            Write-Log "Remediation failed on $($Agent.Hostname): $($_.Exception.Message)" 'ERROR'
        }
    }
}

Function New-EDRReport {
    [CmdletBinding()]
    Param([array]$EvaluatedAgents)
    
    Write-Log "Generating structural insights and reports..."
    
    $Total          = $EvaluatedAgents.Count
    $Compliant      = @($EvaluatedAgents | Where-Object { $_.Compliant })
    $NonCompliant   = @($EvaluatedAgents | Where-Object { -not $_.Compliant })
    
    $CompliantPct   = if ($Total -gt 0) { [math]::Round(($Compliant.Count / $Total) * 100, 2) } else { 0 }
    
    $OutdatedCount  = @($NonCompliant | Where-Object { $_.NonCompliantReasons -match "Outdated" }).Count
    $OfflineCount   = @($NonCompliant | Where-Object { $_.NonCompliantReasons -match "Offline" }).Count
    $BrokenCount    = @($NonCompliant | Where-Object { $_.NonCompliantReasons -match "S1 Agent Broken" }).Count
    $DetectCount    = @($NonCompliant | Where-Object { $_.NonCompliantReasons -match "Detect Only" }).Count
    $UnhealthyCount = @($NonCompliant | Where-Object { $_.NonCompliantReasons -match "Unhealthy/Infected" }).Count
    
    # 1. Export CSV Data
    $CsvPath = Join-Path $ReportDir "S1_NonCompliant_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $NonCompliant | Select-Object Hostname, OS, AgentVersion, DaysOffline, IsHealthy, MitigationMode, NonCompliantReasons | Export-Csv -Path $CsvPath -NoTypeInformation
    
    # 2. Generate HTML View
    $HtmlPath = Join-Path $ReportDir "S1_Summary_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    $HtmlContent = @"
    <html>
    <head>
        <style>
            body { font-family: 'Segoe UI', Arial, sans-serif; }
            .header { background-color: #2b3a42; color: #ffffff; padding: 10px; }
            table { border-collapse: collapse; width: 60%; margin-top: 20px;}
            th, td { border: 1px solid #dddddd; padding: 12px; text-align: left; }
            th { background-color: #f4f4f4; }
            .alert { color: #d9534f; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="header"><h2>SentinelOne Autonomous Coverage Report</h2></div>
        <p><strong>Execution Status:</strong> Completed normally on $(Get-Date)</p>
        <p><strong>Global Compliance Ratio:</strong> <span style="font-size: 1.2rem;">$CompliantPct%</span></p>
        <p>Total Managed Endpoints: $Total | fully Compliant: $($Compliant.Count)</p>
        <table>
            <tr><th>Vector of Non-Compliance</th><th>Impacted Count</th></tr>
            <tr><td>Legacy Agent Versions</td><td>$OutdatedCount</td></tr>
            <tr><td>Offline Protocol (> 24h)</td><td>$OfflineCount</td></tr>
            <tr><td class="alert">S1 Agent Broken / Missing</td><td class="alert">$BrokenCount</td></tr>
            <tr><td>Detect-Only (Vulnerable)</td><td>$DetectCount</td></tr>
            <tr><td>Unhealthy / Compromised states</td><td class="$($UnhealthyCount -gt 0 ? 'alert' : '')">$UnhealthyCount</td></tr>
        </table>
        <p><em>*Detailed host enumerations are attached in CSV format.</em></p>
    </body>
    </html>
"@
    $HtmlContent | Set-Content -Path $HtmlPath
    
    Write-Log "Reports committed to disk successfully."
    
    [PSCustomObject]@{
        TotalCount     = $Total
        CompliantCount = $Compliant.Count
        CompliantPct   = $CompliantPct
        CsvPath        = $CsvPath
        HtmlPath       = $HtmlPath
        SummaryText    = "Coverage Analytics -> Score: $CompliantPct% | Total: $Total | Outdated: $OutdatedCount | Offline: $OfflineCount | Broken Agent: $BrokenCount | Detect: $DetectCount | Unhealthy: $UnhealthyCount"
    }
}

Function Send-EDRReport {
    [CmdletBinding()]
    Param($ReportObj)

    Write-Log "Transmitting execution brief to $($Config.SmtpTo)..."
    try {
        $Body = Get-Content $ReportObj.HtmlPath -Raw
        Send-MailMessage -To $Config.SmtpTo `
                         -From $Config.SmtpFrom `
                         -Subject "[ForgePoint Security] SentinelOne EDR Coverage Brief - $(Get-Date -Format 'yyyy-MM-dd')" `
                         -Body $Body `
                         -BodyAsHtml `
                         -SmtpServer $Config.SmtpServer `
                         -Attachments $ReportObj.CsvPath `
                         -ErrorAction Stop
        Write-Log "Transmission OK."
    } catch {
        Write-Log "SMTP transmission failure: $($_.Exception.Message)" 'ERROR'
    }
}

# ==========================================
# 3. Main Execution Block
# ==========================================
try {
    # Security Baseline: Enforce Modern TLS
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Log "=== STARTING EDR AUTOMATION CYCLE ==="
    Write-Log "Selected Mode: $Mode"

    # Maintenance: Clean logs older than 30 days
    Get-ChildItem -Path $LogDir -Filter "*.log" | 
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | 
        Remove-Item -Force -ErrorAction SilentlyContinue

    # Step 1: Authentication Mapping
    $ApiToken = Get-SecurityToken

    # Step 2: Ingest API Telemetry
    if ($TestGroupId) {
        Write-Log "Running in Scoped Mode. Targeting GroupID: $TestGroupId"
        $EndpointInventory = Get-S1Agents -Token $ApiToken -GroupId $TestGroupId
    } else {
        $EndpointInventory = Get-S1Agents -Token $ApiToken
    }

    $RangerInventory = Get-S1RangerDevices -Token $ApiToken

    if ($EndpointInventory.Count -eq 0) {
        Write-Log "Topology is empty. Zero agents retrieved." 'WARN'
    } else {
        # Step 3: Conformity Processing
        $EvaluationMatrix = Test-EDRCompliance -Agents $EndpointInventory -RangerDevices $RangerInventory
        
        # Step 4: Asset Reporting
        $ReportPayload = New-EDRReport -EvaluatedAgents $EvaluationMatrix
        Write-Log $ReportPayload.SummaryText
        
        # Step 5: Automated Remediation Engine
        if ($Mode -eq 'AllActions') {
            $FailingEndpoints = @($EvaluationMatrix | Where-Object { -not $_.Compliant })
            if ($FailingEndpoints.Count -gt 0) {
                Invoke-Remediation -NonCompliantAgents $FailingEndpoints -Token $ApiToken -RangerDevices $RangerInventory
            } else {
                Write-Log "No non-compliant agents detected. Remediation skipped."
            }
        }

        # Step 6: Dispatch
        if ($Mode -in @('ReportAndEmail', 'AllActions')) {
            Send-EDRReport -ReportObj $ReportPayload
        }
    }

    Write-Log "=== AUTOMATION CYCLE COMPLETED ==="

} catch {
    Write-Log "Fatal Framework Crash: $_" 'ERROR'
    exit 1
}
