---
title: Bash Text Processing
platforms: [Linux]
languages: [Bash]
tasks: [Investigation, Automation, Threat Hunting]
category: Language
tags: [grep, awk, sed, sort, uniq, jq, base64, log parsing]
aliases: [grep awk sed, count unique values, parse logs bash, decode base64, decode powershell encoded command, jq]
difficulty: basic
verified: true
last_verified: 2026-10-05
---

# Bash Text Processing

## grep

```bash
grep -i 'failed password' /var/log/auth.log
grep -E 'error|fail|denied' app.log           # extended regex, alternation
grep -rn 'curl ' /etc/cron* 2>/dev/null       # recursive with line numbers
grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' access.log | sort -u     # extract IPv4 addresses
```

## Count and rank (the stacking pattern)

The single most useful log-analysis pipeline — *what are the most and least common values?*

```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head      # most common
awk '{print $1}' access.log | sort | uniq -c | sort -n  | head      # rarest (long tail)
```

## awk

```bash
awk -F: '$3 >= 1000 {print $1, $6}' /etc/passwd          # field separator, condition
awk '{print $NF}' file                                   # last field
awk '$9 >= 500 {print $7}' access.log                    # HTTP 5xx paths (combined log format)
awk '{sum += $10} END {print sum}' access.log            # total bytes
```

## sed

```bash
sed -n '100,150p' big.log                 # print a line range
sed 's/password=[^&]*/password=REDACTED/g' requests.log
```

## cut, sort, column

```bash
cut -d, -f1,3 data.csv
sort -t, -k3,3nr data.csv | head          # sort CSV by 3rd column, numeric, descending
mount | column -t
```

## jq (JSON)

```bash
jq '.' event.json                                         # pretty-print
jq -r '.[] | [.host, .user, .action] | @tsv' events.json  # array of objects → TSV
jq -r '.data[] | select(.isActive == true) | .computerName' agents.json
jq -c 'select(.severity == "high")' alerts.jsonl          # filter JSON lines
```

## Decode base64 and PowerShell encoded commands

```bash
echo 'aGVsbG8gd29ybGQ=' | base64 -d
```

PowerShell `-EncodedCommand` is base64 of **UTF-16LE** text:

```bash
echo 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=' | base64 -d | iconv -f UTF-16LE -t UTF-8; echo
```

Output: `IEX (New-Object)`. For a reusable decoder that also extracts the payload from a full command line, see [`decode-powershell.py`](../../toolbox/python.md#decode-powershellpy).

## Follow a log live

```bash
tail -F /var/log/auth.log | grep --line-buffered -E 'Accepted|Failed'
```

`-F` keeps following across log rotation; `--line-buffered` prevents output delays when piping.

## Related

- [Bash scripting and automation](automation.md)
- [Linux logs](../../platforms/linux/logs.md)

## Sources

- [GNU grep manual](https://www.gnu.org/software/grep/manual/grep.html)
- [GNU awk manual](https://www.gnu.org/software/gawk/manual/gawk.html)
- [jq manual](https://jqlang.org/manual/)
