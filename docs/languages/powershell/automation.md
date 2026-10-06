---
title: PowerShell Automation and Remoting
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Automation, Incident Response, Administration]
category: Automation
tags: [script template, cmdletbinding, invoke-command, remoting, parallel, scheduled task, whatif]
aliases: [powershell script template, Invoke-Command, run on many computers, ForEach-Object Parallel, using scope, register scheduled task]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# PowerShell Automation and Remoting

## Script template

The template used for every script in the [toolbox](../../toolbox/powershell.md):

```powershell
<#
.SYNOPSIS
    One-line description.
.DESCRIPTION
    What it does, what it changes, what it outputs.
.PARAMETER ComputerName
    Target computers. Defaults to the local computer.
.EXAMPLE
    .\Verb-Noun.ps1 -ComputerName WS01, WS02 | Export-Csv out.csv -NoTypeInformation
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(ValueFromPipeline)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [ValidateRange(1, 365)]
    [int]$Days = 7
)
begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
}
process {
    foreach ($computer in $ComputerName) {
        if ($PSCmdlet.ShouldProcess($computer, 'Collect data')) {
            [pscustomobject]@{ ComputerName = $computer; Days = $Days }
        }
    }
}
```

Conventions: approved verbs (`Get-Verb`), objects as output (never `Write-Host` for data), `-WhatIf` for anything that changes state, comment-based help so `Get-Help .\script.ps1 -Full` works.

## Run on remote computers

```powershell
Invoke-Command -ComputerName WS01, WS02 -ScriptBlock {
    Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess
} | Select-Object PSComputerName, LocalPort, OwningProcess
```

Results carry `PSComputerName`. `-ThrottleLimit` (default 32) controls concurrency.

## Pass local variables into a remote script block

```powershell
$hash = 'A1B2C3...'
Invoke-Command -ComputerName WS01 -ScriptBlock {
    Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { (Get-FileHash $_.FullName).Hash -eq $using:hash }
}
```

`$using:` (or `-ArgumentList` with a `param()` block) is required — the remote session cannot see local variables.

## Persistent sessions and file copy

```powershell
$s = New-PSSession -ComputerName WS01
Copy-Item -Path .\Invoke-EndpointTriage.ps1 -Destination C:\Windows\Temp\ -ToSession $s
Invoke-Command -Session $s -ScriptBlock { & C:\Windows\Temp\Invoke-EndpointTriage.ps1 -OutputPath C:\Windows\Temp\triage }
Copy-Item -Path C:\Windows\Temp\triage -Destination .\cases\WS01 -FromSession $s -Recurse
Remove-PSSession $s
```

## Parallel processing (PowerShell 7)

```powershell
$computers | ForEach-Object -Parallel {
    [pscustomobject]@{ Computer = $_; Online = Test-Connection -TargetName $_ -Count 1 -Quiet }
} -ThrottleLimit 20
```

Inside `-Parallel`, outside variables also need `$using:`.

## Schedule a script

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Daily-Report.ps1"'
$trigger = New-ScheduledTaskTrigger -Daily -At '06:30'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'CC-Daily-Report' -TaskPath '\CommandAndCode\' -Action $action -Trigger $trigger -Principal $principal
```

Scheduled scripts should log to a file (`Start-Transcript`) and exit non-zero on failure so the task result reflects it.

## Related

- [Error handling](error-handling.md)
- [PowerShell toolbox](../../toolbox/powershell.md)
- [Bash scripting and automation](../bash/automation.md)

## Sources

- [about_Remote](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote)
- [about_Remote_Variables ($using:)](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_remote_variables)
- [about_Functions_CmdletBindingAttribute](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_functions_cmdletbindingattribute)
