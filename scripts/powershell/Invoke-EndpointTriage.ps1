<#
.SYNOPSIS
    Collects volatile and persistence data from a Windows endpoint into one folder.
.DESCRIPTION
    Read-only collection, in order of volatility:
      network connections -> processes -> DNS cache -> sessions -> persistence ->
      security tooling -> local accounts -> event log exports -> file hashes.
    Every artefact is written as CSV (or the native format) into a timestamped folder,
    with a manifest of SHA256 hashes and a transcript of the run.

    Nothing on the host is changed apart from creating the output folder.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows. Run elevated.
.PARAMETER OutputPath
    Parent folder for the collection. A subfolder named HOST-yyyyMMdd-HHmmss is created.
.PARAMETER SkipEventLogs
    Do not export .evtx files (faster, smaller).
.PARAMETER LogonHours
    Hours of Security-log logons to summarise. Default 72.
.EXAMPLE
    .\Invoke-EndpointTriage.ps1 -OutputPath D:\Cases\IR-2026-001
.EXAMPLE
    Invoke-Command -ComputerName WS01 -FilePath .\Invoke-EndpointTriage.ps1 -ArgumentList 'C:\Windows\Temp\triage'
.NOTES
    Part of Command & Code. See docs/tasks/incident-response/endpoint-triage.md.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'LogonHours', Justification = 'Used inside Save-Csv script blocks')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputPath,

    [switch]$SkipEventLogs,

    [ValidateRange(1, 720)]
    [int]$LogonHours = 72
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Not running elevated: owners, some services, Security log and Defender exclusions will be incomplete.'
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$root = Join-Path -Path $OutputPath -ChildPath "$env:COMPUTERNAME-$stamp"
New-Item -ItemType Directory -Path $root -Force | Out-Null
Start-Transcript -Path (Join-Path $root 'collection-transcript.txt') | Out-Null
Write-Verbose "Collecting to $root"

function Save-Csv {
    param([string]$Name, [scriptblock]$Collector)
    $file = Join-Path $root "$Name.csv"
    try {
        $data = & $Collector
        if ($data) {
            $data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
            Write-Verbose "[+] $Name ($(@($data).Count) rows)"
        } else {
            Write-Verbose "[ ] $Name (no data)"
        }
    } catch {
        Write-Warning "[!] $Name failed: $($_.Exception.Message)"
    }
}

try {
    # 1. Context
    Save-Csv 'system' {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        [pscustomobject]@{
            CollectedUtc   = (Get-Date).ToUniversalTime().ToString('o')
            TimeZone       = (Get-TimeZone).Id
            ComputerName   = $env:COMPUTERNAME
            Domain         = $cs.Domain
            PartOfDomain   = $cs.PartOfDomain
            OS             = $os.Caption
            Version        = $os.Version
            Build          = $os.BuildNumber
            LastBoot       = $os.LastBootUpTime
            Collector      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
    }

    # 2. Network (most volatile)
    Save-Csv 'net-tcp' {
        Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, CreationTime
    }
    Save-Csv 'net-udp' {
        Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, CreationTime
    }
    Save-Csv 'dns-cache' {
        Get-DnsClientCache | Select-Object Entry, RecordName, Type, Data, TimeToLive
    }
    Save-Csv 'ip-config' {
        Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength
    }
    Save-Csv 'arp' {
        Get-NetNeighbor | Where-Object State -ne 'Unreachable' | Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    }
    Save-Csv 'smb-sessions' {
        Get-SmbSession -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists
    }

    # 3. Processes
    Save-Csv 'processes' {
        Get-CimInstance Win32_Process | ForEach-Object {
            $owner = $null
            try {
                $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
                if ($o.User) { $owner = "$($o.Domain)\$($o.User)" }
            } catch { $owner = $null }
            [pscustomobject]@{
                ProcessId       = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                Name            = $_.Name
                CreationDate    = $_.CreationDate
                Owner           = $owner
                ExecutablePath  = $_.ExecutablePath
                CommandLine     = $_.CommandLine
            }
        }
    }

    # 4. Sessions and accounts
    Save-Csv 'sessions' {
        $ErrorActionPreference = 'Continue'   # quser exits 1 and writes to stderr when nobody is logged on
        $raw = & quser.exe 2>$null
        if ($raw) { $raw | ForEach-Object { [pscustomobject]@{ Line = $_ } } }
    }
    Save-Csv 'local-users' {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, SID
    }
    Save-Csv 'local-admins' {
        try {
            Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | Select-Object Name, ObjectClass, PrincipalSource
        } catch {
            & net.exe localgroup administrators | ForEach-Object { [pscustomobject]@{ Line = $_ } }
        }
    }
    Save-Csv 'logons' {
        $logonScript = Join-Path $PSScriptRoot 'Get-RecentLogons.ps1'
        if (Test-Path $logonScript) { & $logonScript -Hours $LogonHours }
    }

    # 5. Persistence
    Save-Csv 'persistence' {
        $snapshot = Join-Path $PSScriptRoot 'Get-PersistenceSnapshot.ps1'
        if (Test-Path $snapshot) { & $snapshot }
    }
    Save-Csv 'services' {
        Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }
    Save-Csv 'scheduled-tasks' {
        Get-ScheduledTask | ForEach-Object {
            $task = $_
            foreach ($action in @($task.Actions)) {
                $execute = $null
                $arguments = $null
                if ($action.PSObject.Properties['Execute']) { $execute = $action.Execute; $arguments = $action.Arguments }
                [pscustomobject]@{
                    TaskPath  = $task.TaskPath
                    TaskName  = $task.TaskName
                    State     = $task.State
                    Author    = $task.Author
                    RunAs     = $task.Principal.UserId
                    Execute   = $execute
                    Arguments = $arguments
                }
            }
        }
    }

    # 6. Security tooling
    Save-Csv 'defender-status' {
        Get-MpComputerStatus -ErrorAction SilentlyContinue |
            Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected,
                          AntivirusSignatureLastUpdated, AMProductVersion
    }
    Save-Csv 'defender-exclusions' {
        $p = Get-MpPreference -ErrorAction SilentlyContinue
        if ($p) {
            foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
                foreach ($value in @($p.$kind)) {
                    if ($value) { [pscustomobject]@{ Type = $kind; Value = $value } }
                }
            }
        }
    }
    Save-Csv 'defender-detections' {
        Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object InitialDetectionTime, ThreatID, ProcessName, @{ n = 'Resources'; e = { $_.Resources -join ';' } }, ActionSuccess
    }

    # 7. Software and patches
    Save-Csv 'hotfixes' { Get-HotFix | Select-Object HotFixID, Description, InstalledOn }
    Save-Csv 'installed-software' {
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }

    # 8. Event logs
    if (-not $SkipEventLogs) {
        $logDir = Join-Path $root 'evtx'
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        $logs = 'Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational',
                'Microsoft-Windows-Windows Defender/Operational', 'Microsoft-Windows-TaskScheduler/Operational'
        foreach ($log in $logs) {
            $target = Join-Path $logDir (($log -replace '[\\/]', '_') + '.evtx')
            # Windows PowerShell 5.1 turns native stderr into errors when ErrorActionPreference is Stop,
            # so relax it for the native call and rely on the exit code instead.
            $previousPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & wevtutil.exe epl $log $target 2>$null
                if ($LASTEXITCODE -eq 0) { Write-Verbose "[+] evtx $log" } else { Write-Warning "[!] evtx $log export failed (exit $LASTEXITCODE)" }
            } finally {
                $ErrorActionPreference = $previousPreference
            }
        }
    }
}
finally {
    Stop-Transcript | Out-Null
    # 9. Manifest of hashes for chain of custody
    Get-ChildItem -Path $root -File -Recurse |
        Where-Object Name -ne 'manifest-sha256.csv' |
        Get-FileHash -Algorithm SHA256 |
        Select-Object @{ n = 'File'; e = { $_.Path.Substring($root.Length + 1) } }, Hash |
        Export-Csv -Path (Join-Path $root 'manifest-sha256.csv') -NoTypeInformation -Encoding UTF8
    Write-Verbose "Collection written to $root"
}

Get-Item -Path $root
