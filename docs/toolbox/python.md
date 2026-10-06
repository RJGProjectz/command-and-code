---
title: Python Toolbox
type: tool
platforms: [Windows, Linux, Microsoft 365, SentinelOne]
languages: [Python]
tasks: [Automation, Incident Response, Investigation]
category: Tools
tags: [toolbox, scripts, api, decode, powershell, base64]
aliases: [decode encoded powershell, api query script, graph api script, sentinelone api script]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
---

# Python Toolbox

Reusable scripts in `scripts/python/`. Python 3.9+.

## decode-powershell.py

**Problem it solves:** turning an alert's `powershell -enc ...` command line into readable script, including spotting a nested `FromBase64String` second stage.

| | |
| --- | --- |
| Input | a full command line, a bare base64 string, or `-` for stdin |
| Output | decoded script; each nested base64 blob decoded (or identified as gzip) |
| Dependencies | standard library only |
| Safety | decodes only — nothing is executed |

```bash
python decode-powershell.py "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
```

```text
=== Decoded script (UTF-16LE) ===
IEX (New-Object)
```

Related: [Suspicious PowerShell](../tasks/incident-response/suspicious-powershell.md) · [KQL encoded PowerShell](../detection/kql/process-events.md#encoded-powershell)

[Download decode-powershell.py](../../scripts/python/decode-powershell.py)

??? abstract "Source"

    ```python
    --8<-- "python/decode-powershell.py"
    ```

## api-query.py

**Problem it solves:** pulling complete result sets from paginated security APIs (Microsoft Graph, SentinelOne, others) into JSONL or CSV, with retries — without writing a new script each time.

| | |
| --- | --- |
| Inputs | `--url`, `--token-env` (name of an env var), `--auth-scheme` (`Bearer`/`ApiToken`), `--paging` (`odata`/`cursor`/`none`), `--output`, `--format` (`jsonl`/`csv`), `--max-pages` |
| Output | JSON Lines (one item per line) or CSV (nested values JSON-encoded) |
| Dependencies | `requests` |
| Security | token read from the environment, never from arguments (which appear in process listings and shell history) |

```bash
export GRAPH_TOKEN="$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)"
python api-query.py --url 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,accountEnabled' \
    --token-env GRAPH_TOKEN --paging odata --output users.jsonl

export S1_TOKEN='...'
python api-query.py --url 'https://CONSOLE/web/api/v2.1/agents?limit=200' \
    --token-env S1_TOKEN --auth-scheme ApiToken --paging cursor --format csv --output agents.csv
```

Related: [Python HTTP and APIs](../languages/python/http-apis.md) · [PowerShell REST APIs](../languages/powershell/rest-apis.md)

[Download api-query.py](../../scripts/python/api-query.py)

??? abstract "Source"

    ```python
    --8<-- "python/api-query.py"
    ```
