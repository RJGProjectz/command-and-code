<#
.SYNOPSIS
    Lists listening TCP ports and bound UDP endpoints with their owning process.
.DESCRIPTION
    Combines Get-NetTCPConnection / Get-NetUDPEndpoint with Win32_Process so each
    listener shows the process name, path, command line and owner. Read-only.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
.PARAMETER IncludeUdp
    Also return bound UDP endpoints.
.PARAMETER ExcludeLoopback
    Hide listeners bound only to 127.0.0.1 / ::1.
.EXAMPLE
    .\Get-ListeningPorts.ps1 | Format-Table -AutoSize
.EXAMPLE
    .\Get-ListeningPorts.ps1 -IncludeUdp -ExcludeLoopback | Export-Csv listeners.csv -NoTypeInformation
.NOTES
    Part of Command & Code. Run elevated to see the owner of every process.
#>
[CmdletBinding()]
param(
    [switch]$IncludeUdp,
    [switch]$ExcludeLoopback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$processes = @{}
foreach ($p in Get-CimInstance -ClassName Win32_Process) {
    $processes[[int]$p.ProcessId] = $p
}

function Resolve-Owner {
    param($CimProcess)
    try {
        $owner = Invoke-CimMethod -InputObject $CimProcess -MethodName GetOwner -ErrorAction Stop
        if ($owner.User) { return "$($owner.Domain)\$($owner.User)" }
    } catch {
        Write-Verbose "Owner lookup failed for PID $($CimProcess.ProcessId): $($_.Exception.Message)"
    }
    return $null
}

$loopback = @('127.0.0.1', '::1')
$rows = [System.Collections.Generic.List[object]]::new()

$tcp = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $tcp) {
    $rows.Add([pscustomobject]@{ Protocol = 'TCP'; LocalAddress = $conn.LocalAddress; LocalPort = $conn.LocalPort; ProcessId = [int]$conn.OwningProcess })
}

if ($IncludeUdp) {
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($ep in $udp) {
        $rows.Add([pscustomobject]@{ Protocol = 'UDP'; LocalAddress = $ep.LocalAddress; LocalPort = $ep.LocalPort; ProcessId = [int]$ep.OwningProcess })
    }
}

$ownerCache = @{}
foreach ($row in $rows | Sort-Object Protocol, LocalPort, LocalAddress) {
    if ($ExcludeLoopback -and $row.LocalAddress -in $loopback) { continue }

    $proc = $processes[$row.ProcessId]
    if ($proc -and -not $ownerCache.ContainsKey($row.ProcessId)) {
        $ownerCache[$row.ProcessId] = Resolve-Owner -CimProcess $proc
    }

    [pscustomobject]@{
        Protocol     = $row.Protocol
        LocalAddress = $row.LocalAddress
        LocalPort    = $row.LocalPort
        ProcessId    = $row.ProcessId
        ProcessName  = if ($proc) { $proc.Name } else { $null }
        Path         = if ($proc) { $proc.ExecutablePath } else { $null }
        CommandLine  = if ($proc) { $proc.CommandLine } else { $null }
        Owner        = if ($proc) { $ownerCache[$row.ProcessId] } else { $null }
    }
}
