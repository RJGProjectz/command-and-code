---
title: PowerShell Fundamentals and Pitfalls
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Automation, Administration]
category: Language
tags: [powershell, pipeline, operators, splatting, pitfalls, powershell 7, windows powershell]
aliases: [powershell syntax mistakes, powershell gotchas, powershell 5.1 vs 7, splatting, calculated property, comparison operators]
difficulty: basic
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# PowerShell Fundamentals and Pitfalls

The syntax mistakes that cause most broken PowerShell — including most broken AI-generated PowerShell — in one place.

## Objects, not text

Every cmdlet emits objects. Filter and select **properties**, then format **last**.

```powershell
Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, StartType | Sort-Object Name
```

!!! danger "Format-* ends the pipeline"
    `Format-Table` and `Format-List` emit formatting records, not your objects. Never pipe them into `Export-Csv`, `ConvertTo-Json` or `Where-Object`.

## Comparison operators

PowerShell does not use `==`, `!=`, `<` or `>` for comparison.

| Operator | Meaning | Case-sensitive form |
| --- | --- | --- |
| `-eq`, `-ne` | equal / not equal | `-ceq`, `-cne` |
| `-gt`, `-ge`, `-lt`, `-le` | greater / less | |
| `-like`, `-notlike` | wildcard (`*`, `?`) | `-clike` |
| `-match`, `-notmatch` | regex; populates `$Matches` | `-cmatch` |
| `-contains`, `-notcontains` | collection contains **exact** item | |
| `-in`, `-notin` | item is in collection | |

```powershell
'powershell.exe' -like 'power*'                  # True
@('a', 'b') -contains 'a'                        # True
'a' -in @('a', 'b')                              # True
'C:\Temp\x.exe' -match '\\Temp\\'                # True — regex: escape backslashes
'C:\Temp\x.exe' -like '*\Temp\*'                 # True — wildcard: no escaping needed
```

`>` is **redirection**: `if ($a > 5)` writes a file named `5`. Use `-gt`.

## `$null` goes on the left

```powershell
if ($null -eq $result) { 'nothing returned' }
```

With an array on the left, `-eq` **filters** the array instead of returning a boolean, so `$array -eq $null` gives misleading results.

## Reserved automatic variables

Never assign to these: `$PID`, `$Host`, `$Input`, `$Args`, `$Error`, `$Matches`, `$PSItem`/`$_`, `$Home`, `$Profile`, `$true`, `$false`, `$null`. Names are case-insensitive — `$pid = 4` fails because `$PID` is read-only.

## Quoting and string expansion

```powershell
$name = 'svc01'
'Literal: $name'                        # Literal: $name
"Expanded: $name"                       # Expanded: svc01
"Property: $($proc.Path)"               # sub-expression required for properties
"Path: C:\Logs\$name.log"               # fine — $name expands, then .log is text
"Drive: ${env:SystemDrive}\Temp"
```

`"$proc.Path"` expands `$proc` and then appends the literal text `.Path` — always use `$( )` for properties and method calls.

## Splatting instead of backticks

Backtick line continuation breaks silently if anything (even a space) follows it. Splat instead:

```powershell
$params = @{
    FilterHashtable = @{ LogName = 'Security'; Id = 4625 }
    MaxEvents       = 100
    ErrorAction     = 'SilentlyContinue'
}
Get-WinEvent @params
```

A pipe `|` at the end of a line also continues the command safely.

## Calculated properties

```powershell
Get-Process | Select-Object Name, Id, @{ Name = 'MemoryMB'; Expression = { [math]::Round($_.WorkingSet64 / 1MB, 1) } }
```

## Expand a single property

```powershell
Get-Process -Name explorer | Select-Object -ExpandProperty Id      # values
(Get-Process -Name explorer).Id                                    # same, member enumeration
```

`Select-Object Id` returns objects with an `Id` property, not the numbers.

## Building collections

```powershell
$results = [System.Collections.Generic.List[object]]::new()
foreach ($computer in $computers) {
    $results.Add([pscustomobject]@{ Computer = $computer; Online = Test-Connection -ComputerName $computer -Count 1 -Quiet })
}
```

`$array += $item` copies the whole array each time — slow for thousands of items. Simplest of all: assign the loop output directly.

```powershell
$results = foreach ($computer in $computers) { [pscustomobject]@{ Computer = $computer } }
```

## Windows PowerShell 5.1 vs PowerShell 7

| Feature | 5.1 (`powershell.exe`) | 7+ (`pwsh.exe`) |
| --- | --- | --- |
| `&&` and `\|\|` pipeline chains | No | Yes |
| Ternary `$a ? $b : $c` | No | Yes |
| `ForEach-Object -Parallel` | No | Yes |
| `ConvertFrom-Json -AsHashtable` | No | Yes |
| Default `Out-File` / `>` encoding | UTF-16LE | UTF-8 (no BOM) |
| `Export-Csv` type header | Added unless `-NoTypeInformation` | Not added |
| `curl`, `wget` | Aliases for `Invoke-WebRequest` | Real executables |
| `Invoke-RestMethod -SkipCertificateCheck` | No | Yes |

Write for 5.1 unless you control the runtime. Check with `$PSVersionTable.PSVersion`.

## Aliases to avoid in scripts

| Alias | Trap |
| --- | --- |
| `sc` | `Set-Content`, not `sc.exe` |
| `curl`, `wget` | `Invoke-WebRequest` in 5.1 |
| `where`, `?`, `%`, `select`, `gci` | fine interactively; spell out in scripts |

## Execution policy

```powershell
Get-ExecutionPolicy -List
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Execution policy is a safety feature, not a security boundary. `-Scope Process` changes it only for the current session.

## Related

- [Error handling](error-handling.md)
- [Automation and remoting](automation.md)
- [JSON and CSV](json-csv.md)

## Sources

- [about_Comparison_Operators](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_comparison_operators)
- [about_Splatting](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_splatting)
- [Differences between Windows PowerShell 5.1 and PowerShell 7.x](https://learn.microsoft.com/powershell/scripting/whats-new/differences-from-windows-powershell)
