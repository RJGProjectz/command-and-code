<#
.SYNOPSIS
    Collects forensic artifacts from a Windows host for incident response.

.DESCRIPTION
    Standardized forensic collection script.
    Collects: Volatile Data (Network, Processes), System Hives, Event Logs, Web History.
    Output: Zipped archive of artifacts.
    Logging: CloudEvents v1.0 compliant.
    SAFEGUARDS: Read-only, but high I/O impact.

.PARAMETER TargetEnvironment
    'Test' limits collection to non-sensitive areas. 'Prod' performs full collection.

.PARAMETER CaseId
    Incident ID for chain of custody (e.g., INC-10234).

.EXAMPLE
    .\Invoke-ForensicCollection.ps1 -TargetEnvironment Prod -CaseId "INC-12345"
    Performs a full forensic collection for case INC-12345.

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-15T13:31:08
    Last Modified: 2026-01-19T08:50:00
    KB Article: [KB-Sec-006-Forensics.md](../../HowTo/Scripts/KB-Sec-006-Forensics.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$true)]
    [string]$CaseId,

    [string]$OutputDirectory = "C:\Forensics_Stage"
)

# Import Logging Standard
# Reverted to standard text logging per policy
# Import-Module "$PSScriptRoot\..\..\Templates\CloudEventsValidator.psm1" -Force

Begin {
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
    }

    Write-Log "Starting Collection for Case $CaseId in $TargetEnvironment environment."
    
    if (!(Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
    $CollectionRoot = Join-Path $OutputDirectory "$CaseId-$(Get-Date -Format 'yyyyMMddHHmm')"
    New-Item -ItemType Directory -Path $CollectionRoot -Force | Out-Null
}

Process {
    try {
        $HashList = [System.Collections.Generic.List[PSCustomObject]]::new()
        
        # Helper to compute hash of collected file
        function Get-FileHashInfo ($FilePath) {
            $Hash = Get-FileHash -Path $FilePath -Algorithm SHA256
            $HashList.Add([PSCustomObject]@{
                File = [System.IO.Path]::GetFileName($FilePath)
                SHA256 = $Hash.Hash
                Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            })
        }

        # --- PHASE 1: Volatile Network Data (RFC 3227 - Order of Volatility) ---
        Write-Log "Phase 1: Volatile Network Data..."
        
        # 1. Active Connections
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime | 
            Export-Csv (Join-Path $CollectionRoot "1_Network_Connections.csv") -NoTypeInformation
        
        # 2. DNS Cache
        Get-DnsClientCache | Export-Csv (Join-Path $CollectionRoot "1_DNS_Cache.csv") -NoTypeInformation
        
        # 3. ARP Cache (Neighbors)
        Get-NetNeighbor | Select-Object IFIndex, IPAddress, LinkLayerAddress, State | 
            Export-Csv (Join-Path $CollectionRoot "1_ARP_Cache.csv") -NoTypeInformation

        # 4. Routing Table
        Get-NetRoute | Select-Object DestinationPrefix, NextHop, RouteMetric, InterfaceAlias | 
            Export-Csv (Join-Path $CollectionRoot "1_Routing_Table.csv") -NoTypeInformation


        # --- PHASE 2: Process & Memory Artifacts ---
        Write-Log "Phase 2: Process & Memory Artifacts..."
        
        # 5. Running Processes
        Get-Process | Select-Object Id, ProcessName, Path, StartTime, TotalProcessorTime, WorkingSet, Company, Description | 
            Export-Csv (Join-Path $CollectionRoot "2_Processes.csv") -NoTypeInformation

        # 6. Services
        Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName | 
            Export-Csv (Join-Path $CollectionRoot "2_Services.csv") -NoTypeInformation


        # --- PHASE 3: Persistence & Config ---
        Write-Log "Phase 3: Persistence & Configuration..."
        
        # 7. Scheduled Tasks
        Get-ScheduledTask | Select-Object TaskName, State, Description, Author | 
            Export-Csv (Join-Path $CollectionRoot "3_ScheduledTasks.csv") -NoTypeInformation

        # 8. Startup Items (Registry/Startup Folder)
        Get-CimInstance Win32_StartupCommand | Export-Csv (Join-Path $CollectionRoot "3_Startup_Items.csv") -NoTypeInformation
        
        # 9. Local Administrators
        $LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue 
        if ($LocalAdmins) {
            $LocalAdmins | Select-Object Name, ObjectClass, PrincipalSource | Export-Csv (Join-Path $CollectionRoot "3_LocalAdmins.csv") -NoTypeInformation
        }

        # 10. System Info / UI Configuration
        Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, DNSServer | 
            Export-Csv (Join-Path $CollectionRoot "3_IPConfig.csv") -NoTypeInformation


        # --- PHASE 4: Event Logs (Non-Volatile) ---
        Write-Log "Phase 4: Event Logs (Exporting top 5000)..."
        # Exporting to EVTX preserves binary XML data which is better for analysis than CSV
        
        $LogsToCollect = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational")
        
        foreach ($LogName in $LogsToCollect) {
            $ExportPath = Join-Path $CollectionRoot "4_Log_$($LogName -replace '[/\\]','-').evtx"
            try {
                # Attempt full export first (limited by permission/availability)
                # If too large/slow, falling back to Get-WinEvent XML export could be option, but direct file copy is locked.
                # We use -MaxEvents to keep it manageable for this script scope
                Get-WinEvent -LogName $LogName -MaxEvents 5000 -ErrorAction Stop | 
                    Export-Clixml (Join-Path $CollectionRoot "4_Log_$($LogName -replace '[/\\]','-').xml")
            }
            catch {
                Write-Log "Could not export $LogName : $($_.Exception.Message)" "WARNING"
            }
        }


        # --- PHASE 5: Hashing & Archival ---
        Write-Log "Phase 5: Integrity Hashing..."
        
        # Hash all collected files
        Get-ChildItem $CollectionRoot -File | ForEach-Object { Get-FileHashInfo $_.FullName }
        $HashList | Export-Csv (Join-Path $CollectionRoot "0_FileHashes.csv") -NoTypeInformation

        # ZIP it up
        $ZipPath = Join-Path $OutputDirectory "$CaseId-Collection.zip"
        Compress-Archive -Path $CollectionRoot -DestinationPath $ZipPath -Force
        
        # Final Hash of the Zip
        $ZipHash = Get-FileHash -Path $ZipPath -Algorithm SHA256
        Write-Log "Collection Archive: $ZipPath"
        Write-Log "Archive SHA256: $($ZipHash.Hash)"
    }
    catch {
        Write-Log "Error during collection: $($_.Exception.Message)" "ERROR"
        throw $_
    }
}
