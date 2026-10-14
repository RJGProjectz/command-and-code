---
title: Search and Follow Logs by Keyword
type: entry
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - CMD
  - Bash
tasks:
  - Administration
  - Troubleshooting
  - Investigation
verified: true
last_verified: 2026-10-13
difficulty: basic
tags:
  - logs
  - grep
  - select-string
  - tail
  - journalctl
  - get-winevent
  - keyword search
aliases: [grep logs, tail log file, follow log windows, select-string log, search event log message, journalctl grep, findstr log]
---

# Search and Follow Logs by Keyword

Print only the log lines that matter to the console: search a text log or the event log for keywords, show
surrounding lines, follow a log live as it grows, and count matches. Windows and Linux side by side.

!!! warning "Before you run anything"
    Every command here only reads. They were checked against Microsoft Learn and the GNU grep, coreutils and systemd
    man pages (2026-10-13), and the PowerShell and Bash examples were run against sample logs. Reading the Security
    event log and most files under `/var/log` needs administrator or root rights.

## 1. Search a text log for keywords

=== "PowerShell"

    ```powershell
    # Every line containing "error" (Select-String is case-insensitive by default)
    Select-String -Path 'C:\Logs\app.log' -Pattern 'error'

    # Several keywords at once (regex alternation), with 2 lines of context before and after
    Select-String -Path 'C:\Logs\app.log' -Pattern 'error|failed|denied' -Context 2, 2

    # A literal string with regex characters in it: -SimpleMatch, no escaping needed
    Select-String -Path 'C:\Logs\app.log' -Pattern '[ERROR] 0x80070005' -SimpleMatch

    # Only the matching text lines, without file name and line number
    Select-String -Path 'C:\Logs\app.log' -Pattern 'timeout' | ForEach-Object Line

    # Every *.log under a folder tree
    Get-ChildItem -Path 'C:\Logs' -Filter *.log -Recurse -File | Select-String -Pattern 'error'
    ```

=== "Bash"

    ```bash
    grep -i 'error' /var/log/app.log                       # -i: ignore case
    grep -iE 'error|failed|denied' -C 2 /var/log/app.log   # -E: alternation, -C 2: 2 lines of context
    grep -F '[ERROR] 0x80070005' /var/log/app.log          # -F: literal string, no regex
    grep -n 'timeout' /var/log/app.log                     # -n: show line numbers
    grep -rin --include='*.log' 'error' /var/log/myapp/    # every .log under a folder
    zgrep -i 'error' /var/log/syslog.2.gz                  # rotated, compressed logs
    ```

=== "CMD"

    ```bat
    findstr /i "error" C:\Logs\app.log
    rem /r regex, /c: literal phrase with spaces, /n line numbers, /s recurse
    findstr /i /n /c:"access denied" C:\Logs\*.log
    findstr /s /i "error" C:\Logs\*.log
    ```

`Select-String` and `grep -i` ignore case; `findstr` and plain `grep` do not unless you ask (`/i`, `-i`).
`Select-String -CaseSensitive` makes PowerShell strict.

## 2. Follow a log live

=== "PowerShell"

    ```powershell
    # Show the last 20 lines, then keep printing new ones (Ctrl+C to stop)
    Get-Content -Path 'C:\Logs\app.log' -Tail 20 -Wait

    # Follow, but print only lines with a keyword
    Get-Content -Path 'C:\Logs\app.log' -Tail 0 -Wait | Select-String -Pattern 'error|failed'
    ```

=== "Bash"

    ```bash
    tail -n 20 -F /var/log/app.log                         # -F keeps following across log rotation
    tail -n 0 -F /var/log/app.log | grep --line-buffered -iE 'error|failed'
    journalctl -f -u nginx                                 # follow one systemd unit
    ```

`--line-buffered` matters when the output goes into another pipe or a file: without it `grep` holds matches in a
buffer and they appear late.

## 3. Search the Windows event log by keyword

```powershell
# Filter on the server side first (log, IDs, time), then match text in the message
Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 2, 3; StartTime = (Get-Date).AddDays(-1) } |
    Where-Object Message -match 'disk|ntfs|timeout' |
    Select-Object TimeCreated, Id, ProviderName, Message

# Match a value inside the event data, e.g. a user name in 4625 failed logons (elevated)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-4) } |
    Where-Object { $_.Properties[5].Value -eq '<USERNAME>' } |
    Select-Object TimeCreated, @{ N = 'SourceIp'; E = { $_.Properties[19].Value } }
```

Always narrow with `-FilterHashtable` before `Where-Object`: filtering the message text of a whole log is slow. In
4625, property 5 is `TargetUserName` and 19 is `IpAddress` ([event 4625](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)).

## 4. Search the systemd journal by keyword

```bash
journalctl -u ssh --since "1 hour ago" -g 'Failed|Invalid'   # -g: regex on the message (systemd 237+)
journalctl -p err -b                                          # errors and worse since this boot
journalctl --since "2026-10-13 08:00" --until "2026-10-13 09:00" | grep -i 'oom'
```

`-g` is case-insensitive when the pattern is all lower case. The SSH unit is `ssh` on Debian and Ubuntu, `sshd` on RHEL.

## 5. Count and summarise matches

=== "PowerShell"

    ```powershell
    # How many matching lines
    (Select-String -Path 'C:\Logs\app.log' -Pattern 'error').Count

    # Which keyword appears most (one row per keyword)
    Select-String -Path 'C:\Logs\app.log' -Pattern 'error|warning|timeout' -AllMatches |
        ForEach-Object { $_.Matches.Value.ToLower() } | Group-Object | Sort-Object Count -Descending |
        Select-Object Count, Name
    ```

=== "Bash"

    ```bash
    grep -ci 'error' /var/log/app.log                            # -c: count matching lines
    grep -oiE 'error|warning|timeout' /var/log/app.log | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn
    ```

Example output (sample log, run locally):

```text
Count Name
----- ----
    3 error
    2 timeout
    1 warning
```

To keep the matches, send them to a file: [Write command output to files](save-command-output-to-file.md).

## Related

- [Finding files & content discovery](file-search-discovery.md)
- [Windows event logs](../../platforms/windows/event-logs.md)
- [Bash text processing](../../languages/bash/text-processing.md)

## Sources

- [Microsoft Learn — Select-String](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/select-string)
- [Microsoft Learn — Get-Content (-Tail, -Wait)](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-content)
- [Microsoft Learn — Get-WinEvent -FilterHashtable](https://learn.microsoft.com/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)
- [Microsoft Learn — findstr](https://learn.microsoft.com/windows-server/administration/windows-commands/findstr)
- [grep(1)](https://man7.org/linux/man-pages/man1/grep.1.html) · [tail(1)](https://man7.org/linux/man-pages/man1/tail.1.html) · [journalctl(1)](https://man7.org/linux/man-pages/man1/journalctl.1.html)
