---
title: Python JSON and CSV
platforms: [Linux, Windows]
languages: [Python]
tasks: [Automation, Investigation]
category: Data Handling
tags: [json, csv, jsonl, dictreader, encoding]
aliases: [read json python, write csv python, json lines, csv excel utf-8 bom]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Python JSON and CSV

## JSON

```python
import json
from pathlib import Path

data = json.loads(Path("alerts.json").read_text(encoding="utf-8"))
Path("report.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
```

`default=str` serialises values JSON cannot represent natively (e.g. `datetime`).

## JSON Lines (one object per line)

Common for SIEM exports and streaming APIs:

```python
import json

with open("events.jsonl", encoding="utf-8") as fh:
    events = [json.loads(line) for line in fh if line.strip()]

with open("high.jsonl", "w", encoding="utf-8") as out:
    for event in events:
        if event.get("severity") == "high":
            out.write(json.dumps(event) + "\n")
```

## Read CSV as dictionaries

```python
import csv

with open("hosts.csv", newline="", encoding="utf-8-sig") as fh:
    for row in csv.DictReader(fh):
        print(row["Hostname"], row["IP"])
```

`newline=""` is required by the `csv` module. `utf-8-sig` silently strips the BOM that Excel adds.

## Write CSV

```python
import csv

rows = [{"host": "WS01", "port": 4444, "process": "nc"}]
with open("findings.csv", "w", newline="", encoding="utf-8") as fh:
    writer = csv.DictWriter(fh, fieldnames=["host", "port", "process"])
    writer.writeheader()
    writer.writerows(rows)
```

Use `encoding="utf-8-sig"` if the file will be opened in Excel.

## Flatten nested JSON for CSV

```python
def flatten(obj, prefix=""):
    out = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, f"{name}."))
        elif isinstance(value, list):
            out[name] = ";".join(map(str, value))
        else:
            out[name] = value
    return out
```

## Related

- [PowerShell JSON and CSV](../powershell/json-csv.md)
- [Bash jq](../bash/text-processing.md#jq-json)

## Sources

- [json — Python docs](https://docs.python.org/3/library/json.html)
- [csv — Python docs](https://docs.python.org/3/library/csv.html)
