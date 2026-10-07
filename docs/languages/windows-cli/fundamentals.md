---
title: CMD Fundamentals & Syntax
platforms: [Windows, Windows Server]
languages: [CMD, Windows CLI]
tasks: [Administration, Automation]
category: Language
tags: [cmd, batch, windows-cli, syntax, environment-variables, delayed-expansion, redirection, pipes]
aliases: [cmd syntax, batch fundamentals, cmd escaping, delayed expansion, errorlevel, cmd redirection]
difficulty: basic
verified: true
last_verified: 2026-10-06
search:
  boost: 2
---

# CMD Fundamentals & Syntax

Windows Command Prompt (`cmd.exe`) remains indispensable across enterprise administration, WinPE/Windows RE emergency recovery, restricted administrative jump boxes, and live-response EDR agent shells where PowerShell execution is restricted by AppLocker, Constrained Language Mode, or missing assemblies.

Understanding `cmd.exe` mechanics—variable expansion, escaping, stream redirection, and errorlevels—prevents script corruption and execution failures.

---

## 1. Built-in Commands vs. System32 Executables

`cmd.exe` executes two distinct classes of commands:

| Command Type | Examples | Execution Behavior | Calling from PowerShell |
| :--- | :--- | :--- | :--- |
| **Internal Built-ins** | `dir`, `copy`, `del`, `ren`, `move`, `md`, `rd`, `type`, `cls`, `echo`, `set`, `if`, `for` | Implemented directly inside `cmd.exe`. No standalone `.exe` exists in `System32`. Cannot be invoked directly from PowerShell without `cmd /c <command>`. | `cmd.exe /c "dir C:\"` |
| **External Utilities** | `netstat.exe`, `sc.exe`, `schtasks.exe`, `reg.exe`, `wevtutil.exe`, `net.exe`, `whoami.exe`, `ipconfig.exe` | Independent PE binaries residing in `C:\Windows\System32\`. Return integer exit codes upon termination. | Always specify `.exe` extension in PowerShell to avoid alias collisions (e.g. `sc.exe`, not `sc`). |

---

## 2. Variables & Expansion Mechanics

### Standard Variable Expansion (`%VAR%`)
Variables are assigned with `set` (no spaces around `=`) and dereferenced with enclosing percent signs (`%VAR%`):

```bat
:: Variable assignment (NEVER put spaces around the equals sign)
set TARGET_HOST=SRV-DC01
set RETRY_COUNT=3

:: Variable dereferencing
echo Connecting to %TARGET_HOST% with %RETRY_COUNT% attempts...

:: Math operations with /a
set /a TOTAL_ATTEMPTS=%RETRY_COUNT% + 2
echo Total attempts: %TOTAL_ATTEMPTS%

:: User input prompt with /p
set /p USER_INPUT=Enter target IP address: 
```

### Delayed Variable Expansion (`!VAR!`)
By default, `cmd.exe` parses an entire block of parenthesized code (such as an `if` statement or `for` loop) **at once**, expanding all `%VAR%` variables *before* any line in the block executes. This leads to stale variable values in loops.

To evaluate variables at runtime line-by-line, enable **Delayed Expansion** and access variables with exclamation points (`!VAR!`):

```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion

set COUNTER=0
for /l %%i in (1,1,5) do (
    set /a COUNTER+=1
    :: %COUNTER% would always print 0 (evaluated at parse time)
    :: !COUNTER! prints 1, 2, 3, 4, 5 (evaluated dynamically at execution time)
    echo Step %%i: Current counter is !COUNTER!
)

endlocal
```

---

## 3. Quoting & Character Escaping

CMD uses the caret symbol (`^`) as its escape character for reserved shell symbols (`<`, `>`, `|`, `&`, `^`). Inside batch files, the percent sign is escaped with another percent sign (`%%`).

| Character | Meaning in CMD | How to Escape | Example |
| :--- | :--- | :--- | :--- |
| `^` | Shell escape character | `^^` | `echo 2^^3 = 8` |
| `&` | Command chaining / separator | `^&` | `echo Salt ^& Pepper` |
| `\|` | Standard output pipeline | `^\|` | `echo Column1 ^\| Column2` |
| `<`, `>` | Redirection operators | `^<`, `^>` | `echo Use ^<Enter^> to continue` |
| `%` | Variable boundary | `%%` | Inside `.bat`: `for /f %%a in ...`<br>Inside prompt: `for /f %a in ...` |
| `"` | String literal delimiter | Enclose string in `""` | `set "VAR=Value with & | < > symbols"` |

!!! tip "Safe Variable Assignment with Quotes"
    Always enclose the variable name and value together in double quotes: `set "PARAM=value"`. This ensures trailing spaces from editor line endings are not appended to the variable value and prevents shell interpretation of special characters like `&` or `|`.

---

## 4. Streams & Redirection

`cmd.exe` provides standard Unix-equivalent I/O streams: Standard Input (`0`), Standard Output (`1`), and Standard Error (`2`).

```bat
:: Redirect stdout to a file (overwrites existing file)
dir C:\Windows > output.txt

:: Append stdout to an existing file
echo Log message >> application.log

:: Redirect stderr only to error log
net user nonexistentuser 2> errors.log

:: Redirect both stdout and stderr to the same file
dir C:\Staging > output_all.log 2>&1

:: Discard both stdout and stderr completely (silent execution)
ping 127.0.0.1 -n 1 >nul 2>&1

:: Supply a file as standard input
sort < unsorted_list.txt

:: Suppress prompt confirmations using pipe redirection
echo Y | del C:\Staging\temp_files\*.*
```

---

## 5. Command Chaining Operators

CMD supports conditional and unconditional execution operators for chaining multiple commands:

```bat
:: Sequential Unconditional (&): Run command2 regardless of command1 outcome
echo Step 1 & echo Step 2

:: Conditional Success (&&): Run command2 ONLY if command1 exits with ERRORLEVEL 0
ping -n 1 10.0.0.1 >nul && echo Host is reachable

:: Conditional Failure (||): Run command2 ONLY if command1 exits with non-zero ERRORLEVEL
sc.exe query Spooler | findstr /i "RUNNING" >nul || echo Spooler service is stopped!

:: Grouped Ternary Construct
ping -n 1 10.0.0.1 >nul && (
    echo [ONLINE] Host 10.0.0.1 responded.
) || (
    echo [OFFLINE] Host 10.0.0.1 timed out.
)
```

---

## 6. Exit Codes & `%ERRORLEVEL%`

Every external command and most internal commands return an integer exit code when they finish. By convention, `0` represents success, while `1` or greater indicates an error or condition.

### Inspecting ERRORLEVEL

```bat
:: Method 1: Comparison with pseudo-variable %ERRORLEVEL%
sc.exe query LanmanServer >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo LanmanServer query failed with exit code: %ERRORLEVEL%
)

:: Method 2: Legacy syntax (checks if ERRORLEVEL >= N)
sc.exe query LanmanServer >nul 2>&1
if errorlevel 1 (
    echo Warning: An error occurred (code is 1 or greater).
)
```

!!! warning "Gotcha: The 'if errorlevel N' Trap"
    The legacy syntax `if errorlevel 1` evaluates to **true** for ANY exit code greater than or equal to 1. Always use `if %ERRORLEVEL% == 0` or `if %ERRORLEVEL% NEQ 0` for exact, unambiguous equality checks.
