---
title: Shell Command History (PowerShell, CMD, Bash, Zsh)
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
  - Forensics
  - Incident Response
verified: true
last_verified: 2026-10-16
difficulty: basic
tags:
  - history
  - psreadline
  - get-history
  - bash_history
  - zsh_history
  - doskey
  - command line
aliases: [get-history, powershell history file, ConsoleHost_history.txt, HistorySavePath, Get-Content (Get-PSReadLineOption).HistorySavePath, previous commands, bash history, history timestamps, cmd history, doskey /history, clear powershell history, what commands did the user run]
---

# Shell Command History (PowerShell, CMD, Bash, Zsh)

*"What was that command I ran last week?"* *"What did this account type on the host?"* Each shell keeps history
differently: some only in memory for the current window, some in a file per user. This page shows where each one lives,
how to search it, and what it can't tell you.

!!! warning "Before you run anything"
    Reading history is harmless. History files often contain secrets typed on the command line; treat copies as
    sensitive evidence. The PowerShell behaviour on this page was checked on Windows 11 with PowerShell 5.1
    (PSReadLine 2.0.0) and 7.6 (PSReadLine 2.4.5) on 2026-10-16; the rest is checked against Microsoft Learn and the
    bash/zsh manuals.

## At a glance

| Shell | Current session | Saved to disk | Default file |
| :--- | :--- | :--- | :--- |
| PowerShell (built-in) | `Get-History` (`h`) | No — gone when the window closes | — |
| PowerShell (PSReadLine) | Up arrow, `Ctrl+r` | Yes, after every command | `(Get-PSReadLineOption).HistorySavePath` |
| CMD | `doskey /history`, `F7` | No | — |
| Bash | `history` | Yes, when the shell exits | `~/.bash_history` (`$HISTFILE`) |
| Zsh | `history`, `fc -l` | If `HISTFILE` and `SAVEHIST` are set | usually `~/.zsh_history` |
| fish | `history` | Yes | `~/.local/share/fish/fish_history` |

## PowerShell

PowerShell has **two separate histories**:

1. **Built-in session history** — `Get-History`, `Invoke-History`, `Clear-History`. Only the current session; it has
   execution times; it is deleted when the session ends. `$MaximumHistoryCount` defaults to 4096.
2. **PSReadLine history** — what the Up arrow and `Ctrl+r` search. One file per host, shared by every session of that
   user, kept forever. The `*-History` cmdlets do **not** read or clear it.

### This session

```powershell
Get-History                                    # Id, CommandLine
Get-History | Select-Object Id, CommandLine, StartExecutionTime, EndExecutionTime
Get-History -Count 20
Invoke-History 12                              # re-run entry 12 (alias: r 12)
Get-History | Export-Csv "$HOME\session-history.csv" -NoTypeInformation
```

### All past sessions (PSReadLine file)

```powershell
(Get-PSReadLineOption).HistorySavePath          # where the file is
Get-Content (Get-PSReadLineOption).HistorySavePath -Tail 50
Select-String -Path (Get-PSReadLineOption).HistorySavePath -Pattern 'Invoke-WebRequest|iwr |DownloadString'
Get-PSReadLineOption | Select-Object HistorySavePath, HistorySaveStyle, MaximumHistoryCount
```

Default locations (file name is `<HostName>_history.txt`):

| OS | Path |
| :--- | :--- |
| Windows | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| Linux / macOS | `$XDG_DATA_HOME/powershell/PSReadLine/` or `~/.local/share/powershell/PSReadLine/` |

- Windows PowerShell 5.1 and PowerShell 7 console both use **`ConsoleHost_history.txt` in the same folder**, so their
  commands are mixed in one file.
- Other hosts get their own file, e.g. the VS Code extension writes `Visual Studio Code Host_history.txt`. The ISE does
  not use PSReadLine.
- The file has **no timestamps** and no exit codes — only the text typed.
- `HistorySaveStyle` defaults to `SaveIncrementally` (written after each command). `SaveNothing` turns the file off.
- PSReadLine skips lines that look like they contain secrets (`password`, `asplaintext`, `token`, `apikey`, `secret`);
  PSReadLine 2.2+ does this by parsing the command and allows SecretManagement cmdlets such as `Get-Secret`.
  Windows PowerShell 5.1 ships PSReadLine 2.0.0, which predates the improved filter — update it with
  `Install-Module PSReadLine -Scope CurrentUser` if that matters.

### Every user on a Windows host (admin, investigation)

```powershell
Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt' -Force -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, LastWriteTime
```

Copy the files (with `LastWriteTime`) to your evidence folder before reading them on a live host.

### Keep a fuller record

The history file is easy to edit or delete. For audit-quality records use
[PowerShell script block logging (4104) and transcription](../../platforms/windows/event-logs.md#enable-powershell-script-block-logging), or
`Start-Transcript` for your own admin sessions:

```powershell
Start-Transcript -Path "$HOME\Transcripts\$(Get-Date -Format yyyyMMddTHHmmss).txt"
# ... work ...
Stop-Transcript
```

## CMD

```bat
doskey /history
```

`F7` shows a pop-up list, `F8` searches by prefix, `F9` runs an entry by number. CMD history lives only in the console
window's memory and is lost when the window closes; nothing is written to disk. To keep a record, log the work instead,
e.g. `command >> C:\Temp\work.log 2>&1` (see [Save command output to a file](save-command-output-to-file.md)).

## Bash

```bash
history                     # numbered list for this shell
history 20                  # last 20
history | grep -i 'scp\|curl'
!123                        # re-run entry 123;  !! = last command
# Ctrl-r  → reverse search, type part of the command
echo "$HISTFILE"; cat ~/.bash_history | tail -50
```

How it behaves:

- Commands are kept in memory and **written to `$HISTFILE` when the shell exits**. Two open terminals overwrite each
  other unless `shopt -s histappend` is set. `history -a` appends this shell's new lines now; `history -r` reads the
  file in.
- `HISTSIZE` (lines in memory) and `HISTFILESIZE` (lines in the file) cap the size; both default to 500 if unset, but
  distributions often raise them in `~/.bashrc`.
- No timestamps unless `HISTTIMEFORMAT` was set **when the commands were run**; then the file holds `#<epoch>` lines and
  `history` prints them:

```bash
export HISTTIMEFORMAT='%F %T '     # add to ~/.bashrc for future commands
history | tail -5
```

- `HISTCONTROL=ignorespace` (or `ignoreboth`) skips commands that start with a space; `HISTIGNORE` skips patterns.

Make history more useful for admins (`~/.bashrc`):

```bash
shopt -s histappend
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND="history -a${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
```

### Every user on a Linux host (as root)

```bash
sudo find / -xdev \( -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' \
  -o -name 'fish_history' -o -name '*_history.txt' -path '*PSReadLine*' \) -type f -printf '%TY-%Tm-%Td %TH:%TM  %s  %p\n' 2>/dev/null | sort
```

Other files that record typed input: `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.sqlite_history`,
`~/.node_repl_history`, `~/.lesshst`, `~/.viminfo`, `~/.wget-hsts`.

## Zsh and fish

```bash
# zsh
fc -l 1                     # whole in-memory history
fc -li -20                  # last 20 with date/time (needs EXTENDED_HISTORY for saved lines)
echo "$HISTFILE $SAVEHIST"
# EXTENDED_HISTORY file lines look like:  : 1760600000:0;command

# fish
history
history search --contains ssh
```

Zsh writes no file at all unless `HISTFILE` and `SAVEHIST` are set (most distribution and framework defaults set them).

## Investigation notes

Missing or cleared history is itself a finding: clearing it is [T1070.003](https://attack.mitre.org/techniques/T1070/003/), switching it off is [T1690](https://attack.mitre.org/techniques/T1690/):

| Sign | Shell |
| :--- | :--- |
| `~/.bash_history` empty, zero bytes, a symlink to `/dev/null`, or older than the last login | Bash |
| `unset HISTFILE`, `HISTFILE=/dev/null`, `HISTSIZE=0`, `set +o history`, `history -c` in history or profiles | Bash / Zsh |
| PSReadLine file missing, truncated, or `Set-PSReadLineOption -HistorySaveStyle SaveNothing` in a profile | PowerShell |
| `Clear-History` — only clears the session list, **not** the file | PowerShell |

History only shows what was typed **interactively** in that shell. Commands run by scripts, scheduled tasks, cron,
`ssh host 'command'`, web shells or `powershell -Command` do not appear. Use process creation logs (Security 4688 /
Sysmon 1, auditd `execve` — see [auditd](../../platforms/linux/auditd.md)) and script block logging for those.

## Related

- [Command index — all shells](../../references/command-index.md)
- [Save command output to a file](save-command-output-to-file.md)
- [Search logs by keyword](search-logs-by-keyword.md)
- [Linux terminal sessions (tmux, screen)](../../platforms/linux/terminal-sessions.md)
- [Linux live response](../forensics/linux-live-response-forensics.md)

## Sources

- [about_History](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_history)
- [about_PSReadLine — Command history](https://learn.microsoft.com/powershell/module/psreadline/about/about_psreadline)
- [Set-PSReadLineOption](https://learn.microsoft.com/powershell/module/psreadline/set-psreadlineoption)
- [doskey](https://learn.microsoft.com/windows-server/administration/windows-commands/doskey)
- [bash(1) — HISTORY, shell variables](https://man7.org/linux/man-pages/man1/bash.1.html)
- [zsh — History options](https://zsh.sourceforge.io/Doc/Release/Options.html#History)
- [fish — history](https://fishshell.com/docs/current/cmds/history.html)
- [MITRE ATT&CK T1070.003 — Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [MITRE ATT&CK T1690 — Prevent Command History Logging](https://attack.mitre.org/techniques/T1690/)
