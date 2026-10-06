---
title: PowerShell JSON and CSV
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Automation, Investigation]
category: Data Handling
tags: [json, csv, convertto-json, export-csv, depth, encoding]
aliases: [ConvertTo-Json depth, Export-Csv NoTypeInformation, read json powershell, flatten array csv]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# PowerShell JSON and CSV

## Read JSON

```powershell
$data = Get-Content -Path .\alerts.json -Raw | ConvertFrom-Json
$data | Select-Object -First 5
```

`-Raw` reads the file as one string. Without it, 5.1 receives an array of lines and parsing can fail.

## Write JSON — always set `-Depth`

```powershell
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath .\report.json -Encoding utf8
```

!!! danger "Default depth is 2"
    `ConvertTo-Json` silently truncates anything nested deeper than 2 levels into type-name strings (PowerShell 7.1+ also emits a warning). Always pass `-Depth` (max 100).

Single-item arrays: `ConvertTo-Json` outputs an object, not an array. Force an array with `ConvertTo-Json -InputObject @($items) -Depth 10`.

## Hashtable vs PSCustomObject

```powershell
[pscustomobject]@{ Computer = 'WS01'; ProcessId = 1234; Path = 'C:\x.exe' }     # ordered, pipeline-friendly
```

PowerShell 7: `ConvertFrom-Json -AsHashtable` returns hashtables — useful for keys that differ only by case or contain characters awkward as property names.

## Read CSV

```powershell
$hosts = Import-Csv -Path .\hosts.csv
$hosts | Where-Object Owner -eq 'IT' | Select-Object Hostname, IP
Import-Csv -Path .\export.tsv -Delimiter "`t"
```

Every imported value is a **string** — cast before numeric comparison: `[int]$_.Count -gt 10`.

## Write CSV

```powershell
$results | Export-Csv -Path .\results.csv -NoTypeInformation -Encoding utf8
```

`-NoTypeInformation` is required in 5.1 to avoid a `#TYPE` header line (default in 7). Use `-Append` to add rows.

## Flatten arrays before CSV export

CSV cells cannot hold arrays — they export as `System.Object[]`:

```powershell
$users | Select-Object Name, @{ Name = 'Groups'; Expression = { $_.Groups -join ';' } } |
    Export-Csv -Path .\users.csv -NoTypeInformation
```

## Convert between formats

```powershell
Import-Csv .\iocs.csv | ConvertTo-Json -Depth 3 | Out-File .\iocs.json -Encoding utf8
(Get-Content .\iocs.json -Raw | ConvertFrom-Json) | Export-Csv .\iocs2.csv -NoTypeInformation
```

## Related

- [REST APIs](rest-apis.md)
- [Python JSON and CSV](../python/json-csv.md)

## Sources

- [ConvertTo-Json](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/convertto-json)
- [Export-Csv](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/export-csv)
