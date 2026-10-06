<#
.SYNOPSIS
    Troubleshoots NXLog CE agent status, connectivity, and log channel collection on Windows servers.

.DESCRIPTION
    1. Audits the NXLog service (Status, Startup Type, Dependencies).
    2. Parses the NXLog configuration file to identify collector endpoints (TCP) and event channels (im_msvistalog).
    3. Validates network connectivity to the collector.
    4. Verifies the existence of targeted Windows Event Log channels.
    5. Provides actionable recommendations for missing logs or suboptimal service configurations.

.PARAMETER ConfigPath
    Path to the nxlog.conf file. Defaults to 'C:\Program Files (x86)\nxlog\conf\nxlog.conf'.

.PARAMETER TargetEnvironment
    Mandatory standard parameter. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Test-NXLogAgent.ps1 -TargetEnvironment Prod

.NOTES
    Security Domain: Operations
    Created: 2026-02-25
    Author: Antigravity
    KB Article: [KB-Sec-012-NXLog.md](../../HowTo/Scripts/KB-Sec-012-NXLog.md)
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment,

    [string]$ConfigPath = "C:\Program Files (x86)\nxlog\conf\nxlog.conf"
)

# --- Initialize Result Containers ---
$Global:ValidationResults = @()

function Write-Result {
    param([string]$Category, [string]$Status, [string]$Message, [ConsoleColor]$Color)
    $Label = "[$Status]"
    Write-Host "$($Label.PadRight(10)) $Category : $Message" -ForegroundColor $Color
}

Write-Host "`n--- NXLog Troubleshooting Utility [$TargetEnvironment] ---" -ForegroundColor Cyan
Write-Host "Started: $(Get-Date)"

# 1. Service Status and Startup Check
Write-Host "`n[*] Reviewing NXLog Service..." -ForegroundColor Gray
try {
    $Svc = Get-Service -Name "nxlog" -ErrorAction Stop
    $StartupType = (Get-Service -Name "nxlog" | Select-Object -ExpandProperty StartType)
    
    # Check for Delayed Start (Requires registry check as Get-Service doesn't expose it easily)
    $DelayedStart = $false
    try {
        $DelayedStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\nxlog" -Name "DelayedAutostart" -ErrorAction SilentlyContinue).DelayedAutostart -eq 1
    } catch {}

    $StatusColor = if ($Svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Result "Service" $Svc.Status.ToString().ToUpper() "NXLog service is $($Svc.Status)." $StatusColor

    if ($Svc.Status -ne 'Running') {
        Write-Host "    [!] RECOMMENDATION: Start the service using 'Start-Service nxlog'." -ForegroundColor Yellow
    }

    Write-Host "    - Startup Type: $StartupType"
    Write-Host "    - Delayed Start: $($DelayedStart ? 'Enabled' : 'Disabled')"
    
    if ($StartupType -eq 'Automatic' -and -not $DelayedStart) {
        Write-Host "    [!] WARN: 'Automatic' start without 'Delayed Start' may cause ingestion failures if event channels aren't ready at boot." -ForegroundColor Yellow
    }

    if ($Svc.ServicesDependedOn) {
        Write-Host "    - Dependencies: $($Svc.ServicesDependedOn.Name -join ', ')"
    }
} catch {
    Write-Result "Service" "NOT FOUND" "The 'nxlog' service is not installed on this system." Red
}

# 2. Configuration Parsing and Connectivity
Write-Host "`n[*] Parsing Configuration: $ConfigPath" -ForegroundColor Gray
if (Test-Path $ConfigPath) {
    try {
        $ConfigContent = Get-Content $ConfigPath -Raw -ErrorAction Stop
        
        # --- Connectivity Check ---
        # Look for om_tcp modules and extract Host/Port
        $OutputMatches = [regex]::Matches($ConfigContent, '(?ms)<Output\b.*?>.*?Module\s+om_tcp.*?Host\s+(?<Host>[\w\.\-]+).*?Port\s+(?<Port>\d+).*?</Output>')
        
        if ($OutputMatches.Count -gt 0) {
            foreach ($Match in $OutputMatches) {
                $HostAddr = $Match.Groups['Host'].Value
                $PortNum = $Match.Groups['Port'].Value
                
                Write-Host "    -> Found Output Collector: $HostAddr`:$PortNum"
                
                $ConnTest = Test-NetConnection -ComputerName $HostAddr -Port $PortNum -InformationLevel Quiet
                $ConnColor = if ($ConnTest) { 'Green' } else { 'Red' }
                $ConnStatus = if ($ConnTest) { 'REACHABLE' } else { 'FAILED' }
                
                Write-Result "Network" $ConnStatus "Connectivity to $HostAddr on port $PortNum." $ConnColor
            }
        } else {
            Write-Result "Network" "UNKNOWN" "No 'om_tcp' output blocks found in config." Yellow
        }

        # --- Event Channel Existence Check ---
        Write-Host "`n[*] Validating Event Log Channels..." -ForegroundColor Gray
        # Look for im_msvistalog modules and extract Select paths
        $InputBlocks = [regex]::Matches($ConfigContent, '(?ms)<Input\b.*?>.*?Module\s+im_msvistalog.*?Query\s+(?<Query>.*?).*?</Input>')
        
        $CheckedChannels = @{}

        foreach ($Block in $InputBlocks) {
            $Query = $Block.Groups['Query'].Value
            $Channels = [regex]::Matches($Query, 'Path="(?<Path>.*?)"')
            
            foreach ($ChannelMatch in $Channels) {
                $Path = $ChannelMatch.Groups['Path'].Value
                if ($CheckedChannels.ContainsKey($Path)) { continue }
                $CheckedChannels[$Path] = $true

                try {
                    $Log = Get-WinEvent -ListLog $Path -ErrorAction Stop
                    Write-Result "Channel" "OK" "$Path" Green
                } catch {
                    $Action = "Keep"
                    # Heuristic for missing roles
                    if ($Path -match "Directory Service|DNS Server") {
                        $Action = "MISSING ROLE (Domain Controller?)"
                    } elseif ($Path -match "WLAN-AutoConfig") {
                        $Action = "HARDWARE MISSING (WiFi?)"
                    } else {
                        $Action = "UNKNOWN CHANNEL"
                    }
                    Write-Result "Channel" "MISSING" "$Path ($Action)" Red
                    Write-Host "    [!] Suggestion: Comment out corresponding <Input> block to reduce error logging." -ForegroundColor Gray
                }
            }
        }

    } catch {
        Write-Result "Config" "READ ERROR" "Could not read or parse config file." Red
    }
} else {
    Write-Result "Config" "NOT FOUND" "Configuration file not found at $ConfigPath" Red
}

Write-Host "`n--- Troubleshooting Complete ---`n" -ForegroundColor Cyan
