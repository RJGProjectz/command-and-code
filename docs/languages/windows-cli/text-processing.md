---
title: Text Processing & findstr
platforms: [Windows, Windows Server]
languages: [CMD, Windows CLI]
tasks: [Investigation, Automation, Administration]
category: Language
tags: [cmd, findstr, find, text-processing, for-f, parsing, regex, windows-cli]
aliases: [findstr regex, cmd text parsing, for f tokens delims, cmd grep, parse csv batch]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 2
---

# Text Processing & findstr

Windows Command Prompt provides native text-filtering and stream-parsing capabilities through `find`, `findstr`, and the `for /f` iterator. These utilities operate without PowerShell, Python, or third-party binaries, making them essential for high-speed triage, live-response containment, and log auditing.

---

## 1. Quick Comparison: `find` vs. `findstr`

| Feature | `find.exe` | `findstr.exe` |
| :--- | :--- | :--- |
| **Search Engine** | Literal strings only | Regular expressions and literal phrases |
| **Case Sensitivity** | Case-sensitive by default; `/i` for insensitive | Case-sensitive by default; `/i` for insensitive |
| **Multiple Search Strings** | Single string only | Space-delimited search strings or `/g:file` list |
| **Recursive Directory Search** | No | Yes (`/s`) |
| **Line Numbering** | No | Yes (`/n`) |
| **Word Boundaries** | No | Yes (`\<word\>`) |
| **Primary Use Case** | Line counts (`/c`), simple checks | Complex log triage, regex filtering, IoC scans |

---

## 2. Using `findstr`

`findstr` is the Windows native counterpart to `grep`.

### Core Command Switches

```bat
:: Case-insensitive search for a keyword
tasklist | findstr /i "svchost"

:: Invert match: Show all services EXCEPT those in "RUNNING" state
sc.exe query | findstr /v "RUNNING"

:: Exact phrase search containing spaces (use /c:"phrase")
netstat -ano | findstr /i /c:"LISTENING"

:: Search across multiple patterns (space-separated matches EITHER pattern)
tasklist | findstr "powershell.exe cmd.exe"

:: Recursive file search with line numbers
findstr /s /n /i "password" C:\Logs\*.log

:: Print only the filenames that contain the match (/m)
findstr /m /i "unauthorized" C:\Windows\Temp\*.log
```

### Regular Expressions in `findstr`

`findstr` supports basic regular expressions when used with the `/r` switch (or by default when regex meta-characters are present):

| Regex Symbol | Description | Example |
| :--- | :--- | :--- |
| `.` | Any single character | `findstr /r "10\.0\.0\.."` |
| `*` | Zero or more occurrences of preceding character | `findstr /r "err*or"` |
| `^` | Beginning of line | `findstr /r "^[0-9]"` |
| `$` | End of line | `findstr /r "FAILED$"` |
| `[abc]` | Any character in set | `findstr /r "[Ww]arning"` |
| `[^abc]` | Any character NOT in set | `findstr /r "[^0-9]"` |
| `[a-z]` | Character range | `findstr /r "[A-Z0-9]"` |
| `\<` | Beginning of a word | `findstr /r "\<admin"` |
| `\>` | End of a word | `findstr /r "svc\>"` |

!!! warning "`findstr` Limitations"
    `findstr` does NOT support extended regex (`+`, `?`, `{n,m}`, or `|` alternation). To search for alternatives, use space-delimited terms: `findstr "POST GET" access.log`.

---

## 3. Stream Parsing with `for /f`

The `for /f` loop is the standard CMD mechanism for slicing, tokenizing, and transforming structured text output from commands, files, or strings.

### Syntax Breakdown

```bat
for /f "tokens=<nums> delims=<chars> skip=<n> eol=<char>" %%a in ('command') do ( ... )
```

- `tokens=1,2,3*`: Specifies which columns/fields to assign to variables. The first variable is `%%a`, the second is `%%b`, the third is `%%c`, and `*` assigns all remaining text to `%%d`.
- `delims=, `: Defines field delimiter characters (defaults to space and tab).
- `skip=n`: Skips the first `n` lines (useful for bypassing table headers).
- `eol=#`: Treats lines beginning with this character as comments and ignores them.
- `usebackq`: Allows backticks for command execution (`` `command` ``) and double quotes for file paths with spaces (`"C:\My Files\data.csv"`).

---

## 4. Practical Operational Recipes

### Recipe 1: Extract Active Listening Ports and PIDs
Parse `netstat -ano` to extract the local port, connection state, and owning PID:

```bat
@echo off
setlocal EnableDelayedExpansion

echo ==========================================================
echo  Active Listening Ports and Owning Processes
echo ==========================================================

for /f "tokens=2,4,5" %%a in ('netstat -ano ^| findstr /i "LISTENING"') do (
    set "ADDR=%%a"
    set "STATE=%%b"
    set "PID=%%c"
    echo Port: !ADDR!  ^| State: !STATE!  ^| PID: !PID!
)
```

### Recipe 2: Parse Process Names and PIDs from CSV
Extract process details using `tasklist /fo csv`:

```bat
@echo off
setlocal EnableDelayedExpansion

:: tasklist /fo csv /nh emits: "Image Name","PID","Session Name","Session#","Mem Usage"
for /f "tokens=1,2 delims=," %%a in ('tasklist /fo csv /nh') do (
    set "PROC_NAME=%%~a"
    set "PROC_PID=%%~b"
    echo Process: !PROC_NAME! (PID: !PROC_PID!)
)
```

### Recipe 3: Extract Registry Value Directly
Query registry Run keys and extract the path value:

```bat
@echo off
setlocal EnableDelayedExpansion

for /f "tokens=1,2,*" %%a in ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" 2^>nul ^| findstr /i "REG_SZ"') do (
    set "VAL_NAME=%%a"
    set "VAL_TYPE=%%b"
    set "VAL_DATA=%%c"
    echo RunKey: !VAL_NAME! = !VAL_DATA!
)
```

### Recipe 4: Extract IPv4 Address from `ipconfig`
Extract all assigned IPv4 addresses across network adapters:

```bat
@echo off
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i /c:"IPv4 Address"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo Detected Host IP: %%b
    )
)
```
