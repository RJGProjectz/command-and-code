---
title: PowerShell Error Handling
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Automation]
category: Language
tags: [try catch, erroraction, terminating errors, lastexitcode, transcript, strict mode]
aliases: [try catch not working, ErrorAction Stop, non-terminating error, LASTEXITCODE, Start-Transcript]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# PowerShell Error Handling

## Why `try/catch` "doesn't work"

Most cmdlet errors are **non-terminating**: they write an error and continue, so `catch` never runs. Make them terminating:

```powershell
try {
    Get-Item -Path 'C:\does-not-exist' -ErrorAction Stop
} catch {
    Write-Warning "Failed: $($_.Exception.Message)"
}
```

Or for a whole script: `$ErrorActionPreference = 'Stop'` at the top.

## Catch specific exceptions

```powershell
try {
    Get-Item -Path $path -ErrorAction Stop
} catch [System.Management.Automation.ItemNotFoundException] {
    Write-Warning "Not found: $path"
} catch [System.UnauthorizedAccessException] {
    Write-Warning "Access denied: $path"
} catch {
    Write-Error "Unexpected: $($_.Exception.GetType().FullName) $($_.Exception.Message)"
    throw
} finally {
    # always runs — close handles, remove temp files
}
```

Find an error's type after the fact: `$Error[0].Exception.GetType().FullName`.

## Useful error properties

```powershell
catch {
    [pscustomobject]@{
        Message = $_.Exception.Message
        Type    = $_.Exception.GetType().FullName
        Line    = $_.InvocationInfo.ScriptLineNumber
        Command = $_.InvocationInfo.MyCommand.Name
    }
}
```

## Continue past per-item failures

For fleet scripts, record failures and keep going:

```powershell
$failures = [System.Collections.Generic.List[object]]::new()
foreach ($computer in $computers) {
    try {
        Invoke-Command -ComputerName $computer -ScriptBlock { hostname } -ErrorAction Stop
    } catch {
        $failures.Add([pscustomobject]@{ Computer = $computer; Error = $_.Exception.Message })
    }
}
$failures | Export-Csv .\failures.csv -NoTypeInformation
```

## Native executables

External programs do not throw. Check the exit code:

```powershell
& sc.exe query Spooler
if ($LASTEXITCODE -ne 0) { throw "sc.exe failed with exit code $LASTEXITCODE" }
```

PowerShell 7.3+: `$PSNativeCommandUseErrorActionPreference = $true` makes non-zero exit codes honour `$ErrorActionPreference`.

## Strict mode

```powershell
Set-StrictMode -Version Latest
```

Turns references to undefined variables and non-existent properties into errors — catches typos early.

## Logging a run

```powershell
Start-Transcript -Path "C:\Logs\collect-$(Get-Date -Format yyyyMMdd-HHmmss).log"
try {
    # work
} finally {
    Stop-Transcript
}
```

## Related

- [PowerShell fundamentals and pitfalls](fundamentals.md)
- [Automation and remoting](automation.md)

## Sources

- [about_Try_Catch_Finally](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_try_catch_finally)
- [Everything you wanted to know about exceptions](https://learn.microsoft.com/powershell/scripting/learn/deep-dives/everything-about-exceptions)
- [about_Preference_Variables](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_preference_variables)
