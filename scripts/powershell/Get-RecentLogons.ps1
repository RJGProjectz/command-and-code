<#
.SYNOPSIS
    Summarises recent successful and failed logons from the Security log.
.DESCRIPTION
    Reads events 4624 (success) and 4625 (failure) and returns one object per event with
    the fields an analyst needs: time, outcome, user, domain, logon type (number and name),
    source IP, workstation, process and failure status codes. Machine accounts and the
    noisiest service logons can be excluded. Read-only. Requires an elevated session.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
.PARAMETER Hours
    How far back to search. Default 24.
.PARAMETER FailedOnly
    Return only 4625 events.
.PARAMETER IncludeSystemLogons
    Include machine accounts (ending in $) and logon types 0 and 5 (System, Service).
.PARAMETER MaxEvents
    Upper bound on events read per event ID. Default 5000.
.EXAMPLE
    .\Get-RecentLogons.ps1 -Hours 4 | Format-Table Time, Outcome, User, LogonTypeName, SourceIp
.EXAMPLE
    .\Get-RecentLogons.ps1 -FailedOnly -Hours 48 | Group-Object User, SourceIp | Sort-Object Count -Descending
.NOTES
    Part of Command & Code.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 2160)]
    [int]$Hours = 24,

    [switch]$FailedOnly,

    [switch]$IncludeSystemLogons,

    [ValidateRange(1, 1000000)]
    [int]$MaxEvents = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$logonTypeNames = @{
    '0' = 'System'; '2' = 'Interactive'; '3' = 'Network'; '4' = 'Batch'; '5' = 'Service'
    '7' = 'Unlock'; '8' = 'NetworkCleartext'; '9' = 'NewCredentials'; '10' = 'RemoteInteractive'
    '11' = 'CachedInteractive'; '12' = 'CachedRemoteInteractive'; '13' = 'CachedUnlock'
}

$ids = if ($FailedOnly) { @(4625) } else { @(4624, 4625) }
$start = (Get-Date).AddHours(-$Hours)

$events = foreach ($id in $ids) {
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $id; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
}

foreach ($evt in $events | Sort-Object TimeCreated) {
    $data = @{}
    foreach ($node in ([xml]$evt.ToXml()).Event.EventData.Data) {
        $data[$node.Name] = $node.'#text'
    }

    $user = $data['TargetUserName']
    $type = [string]$data['LogonType']
    if (-not $IncludeSystemLogons) {
        if ($user -like '*$' -or $type -in @('0', '5')) { continue }
    }

    [pscustomobject]@{
        Time          = $evt.TimeCreated
        EventId       = $evt.Id
        Outcome       = if ($evt.Id -eq 4624) { 'Success' } else { 'Failure' }
        User          = $user
        Domain        = $data['TargetDomainName']
        LogonType     = $type
        LogonTypeName = $logonTypeNames[$type]
        SourceIp      = $data['IpAddress']
        Workstation   = $data['WorkstationName']
        Process       = $data['ProcessName']
        AuthPackage   = $data['AuthenticationPackageName']
        Status        = $data['Status']
        SubStatus     = $data['SubStatus']
    }
}
