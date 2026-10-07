---
title: Batch Defensive Scripting & Automation
platforms: [Windows, Windows Server]
languages: [CMD, Windows CLI]
tasks: [Automation, Administration]
category: Language
tags: [batch, cmd, scripting, defensive-scripting, loops, subroutines, boilerplate]
aliases: [batch script template, cmd automation, for loops batch, batch functions, call label, dp0]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 2
---

# Batch Defensive Scripting & Automation

While PowerShell is the primary scripting language for modern Windows environments, batch scripts (`.bat` / `.cmd`) remain essential for boot-strap tasks, lightweight wrappers, WinPE execution, unattended installers, and environments where PowerShell execution policies or execution permissions are blocked.

Following defensive scripting standards ensures batch scripts run deterministically without leaking variables or corrupting execution flows.

---

## 1. Enterprise Batch Script Boilerplate

Every production batch script must begin with a standardized header block that isolates environment variables, enables extensions, defines the script's root directory, and enforces error handling.

```bat
@echo off
:: ============================================================================
:: Script: deploy-agent.cmd
:: Description: Automated host configuration and service deployment
:: Author: Command & Code Manual
:: ============================================================================

:: 1. Force strict extension and delayed variable expansion
setlocal EnableExtensions EnableDelayedExpansion

:: 2. Identify the absolute directory of this running script (never assume CWD)
set "SCRIPT_DIR=%~dp0"
set "LOG_DIR=%SCRIPT_DIR%logs"
set "LOG_FILE=%LOG_DIR%\deployment_%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%.log"

:: 3. Prepare logging directory
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

echo [%DATE% %TIME%] Starting execution from %SCRIPT_DIR% >> "%LOG_FILE%"

:: 4. Main script entrypoint
call :Main %*
set "EXIT_CODE=!ERRORLEVEL!"

echo [%DATE% %TIME%] Finished execution with exit code !EXIT_CODE! >> "%LOG_FILE%"

:: 5. Cleanup environment and exit with return code
endlocal & exit /b %EXIT_CODE%

:: ============================================================================
:: Subroutines
:: ============================================================================
:Main
echo [*] Executing core deployment logic...
:: Put payload actions here
exit /b 0
```

---

## 2. Command-Line Arguments & Modifiers

Batch files accept parameters `%1` through `%9`, with `%*` representing all arguments passed to the script. Special **tilde (`~`) parameter modifiers** allow extracting file components:

| Modifier | Function | Example Usage (`%1 = "C:\Audit\logs\scan.txt"`) | Output |
| :--- | :--- | :--- | :--- |
| `%~1` | Strips enclosing quotation marks | `echo Clean argument: %~1` | `C:\Audit\logs\scan.txt` |
| `%~f1` | Resolves full qualified path | `echo Full path: %~f1` | `C:\Audit\logs\scan.txt` |
| `%~d1` | Extracts drive letter only | `echo Drive: %~d1` | `C:` |
| `%~p1` | Extracts path directory only | `echo Path: %~p1` | `\Audit\logs\` |
| `%~n1` | Extracts filename without extension | `echo Name: %~n1` | `scan` |
| `%~x1` | Extracts file extension only | `echo Ext: %~x1` | `.txt` |
| `%~dp1` | Extracts drive and directory path | `echo Dir: %~dp1` | `C:\Audit\logs\` |
| `%~dp0` | **Script directory itself** (drive + path) | `set "ROOT=%~dp0"` | Directory where `.cmd` resides |

### Handling More Than 9 Parameters (`shift`)

When parsing an arbitrary number of parameters:

```bat
:ParseArgs
if "%~1"=="" goto :ArgsDone
echo Processing argument: %~1
if /i "%~1"=="--verbose" set "VERBOSE=1"
if /i "%~1"=="--env" (
    set "TARGET_ENV=%~2"
    shift
)
shift
goto :ParseArgs
:ArgsDone
```

---

## 3. The Five Types of `for` Loops

The `for` loop in CMD provides powerful iteration capabilities across files, folders, numbers, and command outputs. Inside batch files, the loop variable requires two percent signs (`%%i`); in an interactive prompt, use one (`%i`).

### 1. Basic File Loop (`for %%i in (...)`)
Iterates over filenames matching a wildcard:

```bat
for %%f in ("%SCRIPT_DIR%*.log") do (
    echo Found log file: %%~nxf (Size: %%~zf bytes)
)
```

### 2. Directory Loop (`for /d %%d in (...)`)
Iterates over directory names only:

```bat
for /d %%d in ("C:\Users\*") do (
    if exist "%%d\AppData" echo User profile found: %%~nxd
)
```

### 3. Recursive File Tree Loop (`for /r [path] %%f in (...)`)
Walks down all subdirectories recursively:

```bat
:: Find all certificate files under C:\Certificates
for /r "C:\Certificates" %%c in (*.cer *.crt *.pfx) do (
    echo Discovered certificate: %%c
)
```

### 4. Arithmetic Number Range Loop (`for /l %%i in (start,step,end)`)
Generates numerical sequences for retry loops or counters:

```bat
:: Retry up to 5 times with a 2-second sleep between attempts
for /l %%attempt in (1,1,5) do (
    echo [%%attempt/5] Checking service status...
    sc.exe query LanmanServer | findstr /i "RUNNING" >nul
    if !ERRORLEVEL! == 0 (
        echo Service is operational!
        goto :ServiceReady
    )
    timeout /t 2 /nobreak >nul
)
echo [ERROR] Service failed to start within timeout!
:ServiceReady
```

### 5. String & Command Output Parser Loop (`for /f`)
See [Text Processing & findstr](text-processing.md) for parsing delimited data, CSVs, and command stdout.

---

## 4. Subroutines and Functions

CMD implements functions via the `call :Label` mechanism. Subroutines should always terminate with `exit /b [code]`, which returns execution to the caller without exiting the entire script.

```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion

call :ValidateHost "10.0.0.1" HOST_ONLINE
if "!HOST_ONLINE!"=="1" (
    echo Host is alive.
) else (
    echo Host is unreachable.
)

exit /b 0

:: ============================================================================
:: Function: ValidateHost
:: Param 1: IP address or hostname
:: Param 2: Variable name to store result (1 for online, 0 for offline)
:: ============================================================================
:ValidateHost
setlocal
set "TARGET=%~1"
ping -n 1 -w 1000 %TARGET% >nul 2>&1
if !ERRORLEVEL! == 0 (
    set "STATUS=1"
) else (
    set "STATUS=0"
)
:: Return value past endlocal boundary
endlocal & set "%~2=%STATUS%"
exit /b 0
```

---

## 5. Safe Execution with Dry-Run (`--what-if`)

In accordance with strict operational standards, administrative batch scripts must support simulated dry-run execution:

```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "WHAT_IF=0"
if /i "%~1"=="--what-if" set "WHAT_IF=1"
if /i "%~1"=="-WhatIf" set "WHAT_IF=1"

set "TARGET_DIR=C:\Windows\Temp\Staging"

if "!WHAT_IF!"=="1" (
    echo [SIMULATION] Would purge all files in: !TARGET_DIR!
    for %%f in ("!TARGET_DIR!\*.*") do echo   [WHAT-IF] del /f /q "%%f"
) else (
    echo [LIVE ACTION] Purging staging files in: !TARGET_DIR!
    if exist "!TARGET_DIR!\*.*" del /f /q "!TARGET_DIR!\*.*"
)

endlocal
exit /b 0
```
