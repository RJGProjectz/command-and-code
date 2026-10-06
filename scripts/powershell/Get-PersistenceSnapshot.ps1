<#
.SYNOPSIS
    Collects common Windows persistence locations into one list.
.DESCRIPTION
    Read-only snapshot of: Run/RunOnce keys (HKLM, WOW6432Node, every loaded user hive),
    Winlogon Shell/Userinit, Image File Execution Options debuggers, startup folders,
    non-Microsoft-path scheduled tasks, auto-start services, and WMI event subscriptions.
    Each item is flagged when it references a user-writable path or a script interpreter.

    This is a fast first look, not a replacement for Sysinternals Autoruns.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows. Run elevated.
.PARAMETER SuspiciousOnly
    Return only items with at least one flag.
.EXAMPLE
    .\Get-PersistenceSnapshot.ps1 | Out-GridView
.EXAMPLE
    .\Get-PersistenceSnapshot.ps1 -SuspiciousOnly | Export-Csv persistence.csv -NoTypeInformation
.NOTES
    Part of Command & Code.
#>
[CmdletBinding()]
param(
    [switch]$SuspiciousOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$flagPatterns = [ordered]@{
    'UserWritablePath' = '\\Users\\|\\AppData\\|\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\|\\Public\\'
    'ScriptHost'       = '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?\b'
    'Encoded'          = '(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}|frombase64string'
    'Network'          = '(?i)https?://'
}

function Get-RiskFlag {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $hits = foreach ($name in $flagPatterns.Keys) {
        if ($Text -match $flagPatterns[$name]) { $name }
    }
    return ($hits -join ',')
}

function ConvertTo-PersistenceRecord {
    param([string]$Category, [string]$Location, [string]$Name, [string]$Value)
    [pscustomobject]@{
        Category = $Category
        Location = $Location
        Name     = $Name
        Value    = $Value
        Flags    = Get-RiskFlag -Text $Value
    }
}

$results = [System.Collections.Generic.List[object]]::new()

# --- Run keys: machine and every loaded user hive -------------------------------------
$runSubKeys = @(
    'Software\Microsoft\Windows\CurrentVersion\Run'
    'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
)
$keyPaths = [System.Collections.Generic.List[string]]::new()
foreach ($sub in $runSubKeys) { $keyPaths.Add("HKLM:\$sub") }
$keyPaths.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
$keyPaths.Add('HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')

if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
    New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
}
foreach ($sid in Get-ChildItem -Path 'HKU:\' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' }) {
    foreach ($sub in $runSubKeys) { $keyPaths.Add("HKU:\$($sid.PSChildName)\$sub") }
}

foreach ($path in $keyPaths) {
    $key = Get-Item -Path $path -ErrorAction SilentlyContinue
    if (-not $key) { continue }
    foreach ($valueName in $key.GetValueNames()) {
        $results.Add((ConvertTo-PersistenceRecord -Category 'RunKey' -Location $path -Name $valueName -Value ([string]$key.GetValue($valueName))))
    }
}

# --- Winlogon --------------------------------------------------------------------------
$winlogonPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$winlogon = Get-ItemProperty -Path $winlogonPath -ErrorAction SilentlyContinue
if ($winlogon) {
    foreach ($name in 'Shell', 'Userinit') {
        $prop = $winlogon.PSObject.Properties[$name]
        $value = if ($prop) { [string]$prop.Value } else { '' }
        $record = ConvertTo-PersistenceRecord -Category 'Winlogon' -Location $winlogonPath -Name $name -Value $value
        $expected = @{ 'Shell' = '^explorer\.exe$'; 'Userinit' = '^C:\\Windows\\system32\\userinit\.exe,?$' }
        if ($value -notmatch $expected[$name]) {
            $record.Flags = (@($record.Flags, 'NonDefault') | Where-Object { $_ }) -join ','
        }
        $results.Add($record)
    }
}

# --- Image File Execution Options debuggers ---------------------------------------------
$ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($sub in Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue) {
    $debugger = $sub.GetValue('Debugger')
    if ($debugger) {
        $record = ConvertTo-PersistenceRecord -Category 'IFEO' -Location $sub.Name -Name 'Debugger' -Value ([string]$debugger)
        $record.Flags = (@($record.Flags, 'Debugger') | Where-Object { $_ }) -join ','
        $results.Add($record)
    }
}

# --- Startup folders -------------------------------------------------------------------
$startupFolders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
$startupFolders += Get-ChildItem -Path "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
    ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
foreach ($folder in $startupFolders) {
    foreach ($file in Get-ChildItem -Path $folder -File -Force -ErrorAction SilentlyContinue) {
        if ($file.Name -eq 'desktop.ini') { continue }
        $record = ConvertTo-PersistenceRecord -Category 'StartupFolder' -Location $folder -Name $file.Name -Value $file.FullName
        $results.Add($record)
    }
}

# --- Scheduled tasks outside \Microsoft\ -----------------------------------------------
foreach ($task in Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }) {
    foreach ($action in @($task.Actions)) {
        $execute = $null
        $arguments = $null
        if ($action.PSObject.Properties['Execute']) { $execute = $action.Execute; $arguments = $action.Arguments }
        $value = ("$execute $arguments").Trim()
        $results.Add((ConvertTo-PersistenceRecord -Category 'ScheduledTask' -Location $task.TaskPath -Name $task.TaskName -Value $value))
    }
}

# --- Auto-start services ---------------------------------------------------------------
foreach ($svc in Get-CimInstance -ClassName Win32_Service -Filter "StartMode = 'Auto'") {
    $results.Add((ConvertTo-PersistenceRecord -Category 'Service' -Location $svc.StartName -Name $svc.Name -Value ([string]$svc.PathName)))
}

# --- WMI event subscriptions -----------------------------------------------------------
$consumers = Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction SilentlyContinue
foreach ($consumer in @($consumers)) {
    if (-not $consumer) { continue }
    $value = @($consumer.PSObject.Properties['CommandLineTemplate'], $consumer.PSObject.Properties['ScriptText']) |
        Where-Object { $_ -and $_.Value } | ForEach-Object { [string]$_.Value } | Select-Object -First 1
    $record = ConvertTo-PersistenceRecord -Category 'WmiSubscription' -Location $consumer.CimClass.CimClassName -Name ([string]$consumer.Name) -Value ([string]$value)
    $record.Flags = (@($record.Flags, 'WmiConsumer') | Where-Object { $_ }) -join ','
    $results.Add($record)
}

if ($SuspiciousOnly) {
    $results | Where-Object { $_.Flags }
} else {
    $results
}
