---
title: Write Command Output to Files
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
  - Investigation
  - Automation
verified: true
last_verified: 2026-10-13
difficulty: basic
tags:
  - output
  - redirection
  - out-file
  - tee
  - encoding
  - logging
  - transcript
aliases: [save output to text file, powershell write to file, out-file encoding, tee-object, bash redirect to file, append to log file, start-transcript]
---

# Write Command Output to Files

Save what a command prints: overwrite or append, keep errors too, see the output and save it at the same time,
record a whole session, and avoid the encoding trap that makes Windows files unreadable to other tools.

!!! warning "Before you run anything"
    Checked against Microsoft Learn and the Bash and coreutils manuals (2026-10-13); the PowerShell and Bash examples
    were run locally, including the encoding test below. `>` and `Out-File` **overwrite** without asking: use `>>`,
    `-Append` or `-NoClobber` when the file may already exist.

## 1. Overwrite, append, keep errors

=== "PowerShell"

    ```powershell
    Get-Service | Out-File -FilePath 'C:\Temp\services.txt'            # overwrite
    Get-Service | Out-File -FilePath 'C:\Temp\services.txt' -Append    # append
    Get-Process > 'C:\Temp\proc.txt'                                    # same as Out-File
    Get-Process >> 'C:\Temp\proc.txt'                                   # same as Out-File -Append
    Get-ChildItem C:\NoSuchDir 2> 'C:\Temp\errors.txt'                  # errors only (stream 2)
    .\script.ps1 *> 'C:\Temp\all-output.txt'                            # every stream: output, error, warning, verbose
    Add-Content -Path 'C:\Temp\run.log' -Value "$(Get-Date -Format s) backup finished"   # one line, appended
    ```

=== "Bash"

    ```bash
    ls -la /etc > /tmp/etc-list.txt              # overwrite
    ls -la /etc >> /tmp/etc-list.txt             # append
    find / -name '*.conf' 2> /tmp/errors.txt     # errors only
    ./script.sh > /tmp/all.txt 2>&1              # output and errors (order matters: > first, then 2>&1)
    echo "$(date -u +%FT%TZ) backup finished" >> /var/log/mybackup.log
    set -o noclobber                             # from now on > refuses to overwrite; >| forces it
    ```

=== "CMD"

    ```bat
    ipconfig /all > C:\Temp\ipconfig.txt
    netstat -ano >> C:\Temp\netstat.txt
    dir C:\NoSuchDir 2> C:\Temp\errors.txt
    myjob.cmd > C:\Temp\job.log 2>&1
    ```

## 2. See it and save it (tee)

=== "PowerShell"

    ```powershell
    Get-NetTCPConnection -State Listen | Tee-Object -FilePath 'C:\Temp\listeners.txt'
    Get-NetTCPConnection -State Listen | Tee-Object -FilePath 'C:\Temp\listeners.txt' -Append
    Get-Process | Tee-Object -Variable procs | Sort-Object CPU -Descending | Select-Object -First 5   # keep a copy in $procs
    ```

=== "Bash"

    ```bash
    ss -tulpn | tee /tmp/listeners.txt
    ss -tulpn | tee -a /tmp/listeners.txt        # append
    sudo ss -tulpn | sudo tee /root/listeners.txt > /dev/null   # write where only root can
    ```

`sudo cmd > /root/file` fails because the redirection runs in your own shell, not as root; pipe into `sudo tee` instead.

## 3. Pick the right format

```powershell
Get-Process | Format-Table -AutoSize | Out-File 'C:\Temp\proc.txt' -Width 300   # stop long columns being cut off
Get-Process | Select-Object Name, Id, CPU | Export-Csv 'C:\Temp\proc.csv' -NoTypeInformation   # for Excel or a SIEM
Get-Process | Select-Object Name, Id, CPU | ConvertTo-Json -Depth 3 | Set-Content 'C:\Temp\proc.json'
```

Text files are for people; CSV and JSON are for tools. `Export-Csv` writes the objects' properties, so do not put
`Format-Table` in front of it.

## 4. The Windows encoding trap

The same line written by different commands, checked byte by byte on Windows 11 (first bytes of each file):

```text
Windows PowerShell 5.1   > / Out-File / Tee-Object   FF FE 68 00 ...   UTF-16 LE with BOM
Windows PowerShell 5.1   Set-Content / Add-Content   68 E9 6C ...      ANSI (system code page)
PowerShell 7             all of the above            68 C3 A9 6C ...   UTF-8, no BOM
```

A UTF-16 file shows up in `grep`, Git or a Linux tool as text with a NUL between every character. Worse, in 5.1
`>>` onto a file that `Set-Content` created appends UTF-16 to an ANSI file, leaving one file in two encodings
(tested: `first` readable, `s.e.c.o.n.d` after it). In Windows PowerShell 5.1, say what you want:

```powershell
Get-Service | Out-File 'C:\Temp\services.txt' -Encoding utf8          # 5.1: UTF-8 with BOM
Add-Content 'C:\Temp\services.txt' -Value 'done' -Encoding utf8
```

Background: [Cross-platform data handling](../../fundamentals/systems/cross-platform-data-handling.md).

## 5. Name files so they never collide

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Get-WinEvent -LogName System -MaxEvents 500 | Export-Csv "C:\Temp\$env:COMPUTERNAME-system-$stamp.csv" -NoTypeInformation
```

```bash
stamp=$(date -u +%Y%m%dT%H%M%SZ)
journalctl -b --no-pager > "/tmp/$(hostname)-journal-$stamp.txt"
```

Avoid `%date%` in CMD file names: its format follows the user's regional settings.

## 6. Record a whole session

=== "PowerShell"

    ```powershell
    Start-Transcript -Path "C:\Temp\session-$(Get-Date -Format yyyyMMdd-HHmmss).txt"   # everything typed and printed
    # ... work ...
    Stop-Transcript
    ```

=== "Bash"

    ```bash
    script -q /tmp/session-$(date +%Y%m%d-%H%M%S).txt    # type 'exit' to stop recording
    exec > >(tee -a /var/log/myscript.log) 2>&1           # first line of a script: log everything it prints
    ```

A transcript is good evidence of what an admin did during an incident; store it with the case notes.

## Related

- [Search and follow logs by keyword](search-logs-by-keyword.md)
- [PowerShell JSON and CSV](../../languages/powershell/json-csv.md)
- [Windows CLI fundamentals](../../languages/windows-cli/fundamentals.md)

## Sources

- [Microsoft Learn — about_Redirection](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_redirection)
- [Microsoft Learn — Out-File](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/out-file)
- [Microsoft Learn — Tee-Object](https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/tee-object)
- [Microsoft Learn — about_Character_Encoding](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_character_encoding)
- [Microsoft Learn — Start-Transcript](https://learn.microsoft.com/powershell/module/microsoft.powershell.host/start-transcript)
- [GNU Bash manual — Redirections](https://www.gnu.org/software/bash/manual/html_node/Redirections.html) · [tee(1)](https://man7.org/linux/man-pages/man1/tee.1.html) · [script(1)](https://man7.org/linux/man-pages/man1/script.1.html)
