<#
.SYNOPSIS
    Read-only CIS block monitor for Windows: programs, scripts and installers blocked (or audit-flagged) by hardening controls.

.DESCRIPTION
    Script Name: FUNC_PS_GET_CIS_BLOCK_EVENTS
    Reads the Windows event logs below and emits one object and one NDJSON event (GOLDEN_STANDARDS 4.7) per
    block, with the control that blocked it and, when a CIS catalog is available, the CIS recommendation that
    configures that control. Event IDs are from Microsoft Learn (see .NOTES):

      Control             Log                                              Blocked            Audited (would block)
      AppLocker           Microsoft-Windows-AppLocker/EXE and DLL          8004               8003
      AppLocker           Microsoft-Windows-AppLocker/MSI and Script       8007               8006
      AppLocker           Microsoft-Windows-AppLocker/Packaged app-*       8022, 8025         8021, 8024
      AppControl (WDAC)   Microsoft-Windows-CodeIntegrity/Operational      3077, 3033         3076, 3034
      AppControl scripts  Microsoft-Windows-AppLocker/MSI and Script       8029, 8036, 8040   8028, 8039
      ASR rules           Microsoft-Windows-Windows Defender/Operational   1121               1122 (1129 = user override)
      Controlled folders  Microsoft-Windows-Windows Defender/Operational   1123, 1127         1124, 1128
      Windows Installer   Application, provider MsiInstaller               1007, 1008, 1044   -

    UAC: "Automatically deny elevation requests" (CIS 2.3.17.3 on Windows 11) writes no documented event, so
    denied elevations cannot be reported from the event log.

    The CIS mapping is looked up by title in the catalog (scripts/cis/catalogs/*.json) so no recommendation
    number is hard-coded: ASR -> the 'Configure Attack Surface Reduction rules' recommendation, when the catalog
    has it. AppLocker, App Control and Controlled folder access are organization policies with no CIS Level 1/2
    number, and Windows Installer blocks 1007/1008 come from software restriction or AppLocker policy, not from a
    CIS setting; cis_id is then empty.

.PARAMETER TargetEnvironment
    'Test' or 'Prod'. Defaults to 'Test'. Read-only in both; recorded in each event.

.PARAMETER Hours
    How far back to read. Default 24.

.PARAMETER IncludeAudit
    Also report audit-mode (would-block) events. Default: blocks only.

.PARAMETER InputPath
    XML file with exported events (<Events><Event>...</Event></Events>) to parse instead of the live logs. This
    is how the Pester fixtures run on Linux CI.

.PARAMETER CatalogPath
    CIS catalog JSON used to name the recommendation. Default: the first catalog in ..\cis\catalogs.

.PARAMETER LogPath
    Directory for the text log and NDJSON event log. Defaults to .\Logs beside the script.

.EXAMPLE
    .\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -Hours 72 | Format-Table event_time, control, result, path, cis_id

.EXAMPLE
    .\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -IncludeAudit -WhatIf
    Dry run: lists the logs and event IDs that would be read.

.EXAMPLE
    Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 50 |
        ForEach-Object { $_.ToXml() } | Set-Content .\ci.xml   # wrap in <Events>...</Events>, then:
    .\FUNC_PS_GET_CIS_BLOCK_EVENTS.ps1 -InputPath .\ci-events.xml -IncludeAudit

.OUTPUTS
    PSCustomObject per block event. The same events and the run log are appended as NDJSON to
    <LogPath>\FUNC_PS_GET_CIS_BLOCK_EVENTS.ndjson.

.NOTES
    Purpose: Show what the hardening actually stopped, so a block can be traced to its control and tuned or escalated.
    Security Context: blocked execution of unsigned or user-writable binaries, scripts and Office child processes is
        an early sign of payload delivery (T1204.002, T1059.001) and of attempts to get around application control.
    Security Domain: Compliance / Detection
    Author: RJGProjectz
    Version: 1.0.0
    Created: 2026-10-19T16:30:00Z
    Last Modified: 2026-10-19T16:30:00Z
    KB Article: [CIS block monitor](../../docs/tasks/hardening/cis-block-monitor.md)
    Source Repo: [AppLocker events](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker),
        [App Control event IDs](https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations),
        [ASR events](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-windows-events),
        [Windows Installer event logging](https://learn.microsoft.com/windows/win32/msi/event-logging)
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 8760)]
    [int]$Hours = 24,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeAudit,

    [Parameter(Mandatory = $false)]
    [string]$InputPath,

    [Parameter(Mandatory = $false)]
    [string]$CatalogPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = (Join-Path $PSScriptRoot 'Logs')
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ScriptName = 'FUNC_PS_GET_CIS_BLOCK_EVENTS'
$ScriptVersion = '1.0.0'
$ExecutionId = [guid]::NewGuid().ToString()
$HostName = [Environment]::MachineName

# Event ID -> control and verdict. Channel names as in Event Viewer (Get-WinEvent -LogName).
$script:EventMap = @(
    @{ Log = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8004; Control = 'AppLocker'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = 8003; Control = 'AppLocker'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8007; Control = 'AppLocker'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8006; Control = 'AppLocker'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8029; Control = 'AppControl'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8028; Control = 'AppControl'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8036; Control = 'AppControl'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8040; Control = 'AppControl'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = 8039; Control = 'AppControl'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Execution'; Id = 8022; Control = 'AppLocker'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Execution'; Id = 8021; Control = 'AppLocker'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Deployment'; Id = 8025; Control = 'AppLocker'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Deployment'; Id = 8024; Control = 'AppLocker'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3077; Control = 'AppControl'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033; Control = 'AppControl'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3076; Control = 'AppControl'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3034; Control = 'AppControl'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1121; Control = 'ASR'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1122; Control = 'ASR'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1129; Control = 'ASR'; Result = 'UserOverride' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1123; Control = 'ControlledFolderAccess'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1127; Control = 'ControlledFolderAccess'; Result = 'Blocked' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1124; Control = 'ControlledFolderAccess'; Result = 'Audited' }
    @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1128; Control = 'ControlledFolderAccess'; Result = 'Audited' }
    @{ Log = 'Application'; Id = 1007; Control = 'WindowsInstaller'; Result = 'Blocked'; Provider = 'MsiInstaller' }
    @{ Log = 'Application'; Id = 1008; Control = 'WindowsInstaller'; Result = 'Blocked'; Provider = 'MsiInstaller' }
    @{ Log = 'Application'; Id = 1044; Control = 'WindowsInstaller'; Result = 'Blocked'; Provider = 'MsiInstaller' }
)

# ASR rule GUIDs (ASR rules reference) -> rule name, so a 1121 event names the rule that fired.
$script:AsrRules = @{
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet a prevalence, age, or trusted list criterion'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
}

# Title patterns used to find the CIS recommendation for a control in the catalog.
$script:CisTitlePattern = @{
    ASR = 'Attack Surface Reduction'
}

# --- Logging Helper ---
function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red' }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
    if (-not (Test-Path -LiteralPath $LogPath)) { $null = New-Item -ItemType Directory -Path $LogPath -Force }
    Add-Content -LiteralPath (Join-Path $LogPath 'ScriptLog.log') -Value "[$timestamp] [$Level] $Message"
    $entry = [ordered]@{
        timestamp = $timestamp; host = $HostName; tool = $ScriptName; version = $ScriptVersion
        execution_id = $ExecutionId; environment = $TargetEnvironment; level = $Level; action = 'log'; message = $Message
    }
    Add-Content -LiteralPath (Join-Path $LogPath "$ScriptName.ndjson") -Value ($entry | ConvertTo-Json -Compress)
}

function Get-EventDataMap {
    <#
    .SYNOPSIS
        Flattens an event's EventData (Data Name=...) and UserData leaf elements into a name -> value hashtable.
    #>
    param([Parameter(Mandatory = $true)][xml]$EventXml)
    $map = @{}
    $root = $EventXml.DocumentElement
    foreach ($node in $root.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ($name) { $map[$name] = $node.InnerText }
    }
    foreach ($node in $root.SelectNodes("//*[local-name()='UserData']//*[not(*)]")) {
        if (-not $map.ContainsKey($node.LocalName)) { $map[$node.LocalName] = $node.InnerText }
    }
    return $map
}

function Get-FirstValue {
    param([hashtable]$Map, [string[]]$Names)
    foreach ($name in $Names) {
        # AppLocker writes RuleName '-' when no rule matched (default deny).
        if ($Map.ContainsKey($name) -and $Map[$name] -and $Map[$name] -ne '-') { return [string]$Map[$name] }
    }
    return ''
}

function Find-CisRecommendation {
    <#
    .SYNOPSIS
        CIS ID and title for a control, found by title pattern in the loaded catalog (empty when none).
    #>
    param([string]$Control, $Catalog)
    if ($null -eq $Catalog -or -not $script:CisTitlePattern.ContainsKey($Control)) { return @('', '') }
    $match = @($Catalog.checks | Where-Object { $_.title -match $script:CisTitlePattern[$Control] }) | Select-Object -First 1
    if ($null -eq $match) { return @('', '') }
    return @([string]$match.id, [string]$match.title)
}

function ConvertFrom-CisBlockEvent {
    <#
    .SYNOPSIS
        Turns one event (XML) into a block record, or $null when the event is not a block/audit event.
    .EXAMPLE
        ConvertFrom-CisBlockEvent -EventXml $winEvent.ToXml() -Catalog $catalog
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EventXml,
        $Catalog
    )
    [xml]$doc = $EventXml
    $system = $doc.DocumentElement.SelectSingleNode("*[local-name()='System']")
    $eventId = [int]$system.SelectSingleNode("*[local-name()='EventID']").InnerText
    $channel = $system.SelectSingleNode("*[local-name()='Channel']").InnerText
    $provider = $system.SelectSingleNode("*[local-name()='Provider']").GetAttribute('Name')
    $created = $system.SelectSingleNode("*[local-name()='TimeCreated']").GetAttribute('SystemTime')
    $entry = $script:EventMap | Where-Object {
        $_.Id -eq $eventId -and $_.Log -eq $channel -and (-not $_.ContainsKey('Provider') -or $_.Provider -eq $provider)
    } | Select-Object -First 1
    if ($null -eq $entry) { return $null }

    $data = Get-EventDataMap -EventXml $doc
    $path = Get-FirstValue -Map $data -Names @('FullFilePath', 'FilePath', 'File Name', 'Path', 'File', 'PackageFullName')
    $process = Get-FirstValue -Map $data -Names @('Process Name', 'ProcessName', 'Process', 'TargetProcessName')
    $user = Get-FirstValue -Map $data -Names @('User', 'TargetUser', 'UserName')
    if (-not $user) {
        $security = $system.SelectSingleNode("*[local-name()='Security']")
        if ($null -ne $security) { $user = $security.GetAttribute('UserID') }
    }
    $rule = Get-FirstValue -Map $data -Names @('RuleName', 'PolicyName', 'ID')
    if ($entry.Control -eq 'ASR' -and $data.ContainsKey('ID')) {
        $guid = ([string]$data['ID']).Trim('{}').ToLowerInvariant()
        $rule = if ($script:AsrRules.ContainsKey($guid)) { "$($script:AsrRules[$guid]) ($guid)" } else { $guid }
    }
    if ($entry.Control -eq 'WindowsInstaller' -and -not $path) {
        $path = Get-FirstValue -Map $data -Names @('param1')
        if (-not $path) {
            $first = $doc.DocumentElement.SelectSingleNode("//*[local-name()='EventData']/*[local-name()='Data']")
            if ($null -ne $first) { $path = $first.InnerText }
        }
    }
    $cis = Find-CisRecommendation -Control $entry.Control -Catalog $Catalog
    return [PSCustomObject][ordered]@{
        event_time = $created
        control    = $entry.Control
        result     = $entry.Result
        event_id   = $eventId
        channel    = $channel
        path       = $path
        process    = $process
        user       = $user
        rule       = $rule
        cis_id     = $cis[0]
        cis_title  = $cis[1]
    }
}

# --- Begin ---
Write-Log "Starting $ScriptName $ScriptVersion in [$TargetEnvironment] mode (read-only)."

if (-not $CatalogPath) {
    $first = @(Get-ChildItem -Path (Join-Path $PSScriptRoot '..\cis\catalogs') -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name) |
        Select-Object -First 1
    if ($null -ne $first) { $CatalogPath = $first.FullName }
}
$catalog = $null
if ($CatalogPath -and (Test-Path -LiteralPath $CatalogPath)) {
    $catalog = Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Log "CIS mapping from $(Split-Path -Leaf $CatalogPath) ($($catalog.benchmark) v$($catalog.version))."
} else {
    Write-Log 'No CIS catalog found: cis_id stays empty (build one, see docs/tasks/hardening/windows-11-cis-audit-tool.md).' 'WARN'
}

$wanted = @($script:EventMap | Where-Object { $IncludeAudit -or $_.Result -ne 'Audited' })
$xmlEvents = New-Object System.Collections.Generic.List[string]
if ($InputPath) {
    [xml]$exported = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8
    foreach ($node in $exported.DocumentElement.SelectNodes("*[local-name()='Event']")) { $xmlEvents.Add($node.OuterXml) }
    Write-Log "Parsing $($xmlEvents.Count) exported event(s) from $InputPath."
} elseif ($PSCmdlet.ShouldProcess("$HostName event logs", 'Read block events (no change)')) {
    $since = (Get-Date).AddHours(-$Hours)
    foreach ($group in ($wanted | Group-Object { $_.Log })) {
        $filter = @{ LogName = $group.Name; Id = @($group.Group | ForEach-Object { $_.Id }); StartTime = $since }
        try {
            foreach ($winEvent in @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)) { $xmlEvents.Add($winEvent.ToXml()) }
        } catch [System.Exception] {
            # "No events were found" and missing channels (e.g. AppLocker on Server Core) are not errors.
            Write-Verbose "$($group.Name): $($_.Exception.Message)"
        }
    }
} else {
    $wanted | Group-Object { $_.Log } | ForEach-Object {
        Write-Log "[WHATIF] Would read $($_.Name) event IDs $((@($_.Group | ForEach-Object { $_.Id })) -join ', ') for the last $Hours h."
    }
    return
}

$count = 0
foreach ($xmlEvent in $xmlEvents) {
    $record = ConvertFrom-CisBlockEvent -EventXml $xmlEvent -Catalog $catalog
    if ($null -eq $record -or (-not $IncludeAudit -and $record.result -eq 'Audited')) { continue }
    $count++
    $line = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); host = $HostName; tool = $ScriptName
        version = $ScriptVersion; execution_id = $ExecutionId
        level = if ($record.result -eq 'Audited') { 'INFO' } else { 'WARN' }
        message = "$($record.control) $($record.result) $($record.path)"; environment = $TargetEnvironment
        action = 'cis.block'; target = $record.path; result = $record.result
    }
    foreach ($property in $record.PSObject.Properties) { if (-not $line.Contains($property.Name)) { $line[$property.Name] = $property.Value } }
    Add-Content -LiteralPath (Join-Path $LogPath "$ScriptName.ndjson") -Value ($line | ConvertTo-Json -Compress)
    $record
}

# --- End ---
Write-Log "Script completed: $count block event(s)."
