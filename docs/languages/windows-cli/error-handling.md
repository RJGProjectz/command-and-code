---
title: CMD Error Handling & Exit Codes
platforms: [Windows, Windows Server]
languages: [CMD, Windows CLI]
tasks: [Automation, Troubleshooting, Administration]
category: Language
tags: [cmd, errorlevel, error-handling, exit-codes, robocopy, conditional-execution]
aliases: [cmd error handling, errorlevel pitfalls, robocopy exit codes, batch try catch, batch exit codes]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 2
---

# CMD Error Handling & Exit Codes

Unlike PowerShell which raises structured exceptions, `cmd.exe` communicates command outcomes through integer exit codes stored in the `%ERRORLEVEL%` pseudo-variable. Misinterpreting exit codes or relying on legacy constructs is the most common cause of silent failures in Windows administration scripts.

---

## 1. `%ERRORLEVEL%` Mechanics & Common Pitfalls

### Exact Equality vs. Legacy Range Checks

In batch scripts, two syntaxes exist for checking exit codes. They behave completely differently:

```bat
:: SYNTAX A: Legacy Range Check (checks if ERRORLEVEL >= 1)
sc.exe query Spooler >nul 2>&1
if errorlevel 1 (
    echo Error occurred!
)

:: SYNTAX B: Exact Variable Comparison (Recommended)
sc.exe query Spooler >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error occurred with specific code: %ERRORLEVEL%
)
```

| Evaluation Syntax | Code `0` | Code `1` | Code `2` | Code `16` | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `if errorlevel 1` | False | **True** | **True** | **True** | Evaluates true for ANY code $\ge 1$. Cannot detect exact codes without descending ordering. |
| `if %ERRORLEVEL% == 1` | False | **True** | False | False | Evaluates true ONLY when code is precisely `1`. |
| `if %ERRORLEVEL% NEQ 0` | False | **True** | **True** | **True** | Clear and unambiguous check for non-zero failure. |

!!! danger "Never Set a Variable Named ERRORLEVEL"
    If a script runs `set ERRORLEVEL=0`, it creates a user environment variable that shadows the dynamic engine pseudo-variable. `cmd.exe` will then permanently report `0` regardless of what commands execute! Always use `(call )` to reset the dynamic errorlevel without setting an explicit variable.

---

## 2. The Robocopy Exit Code Bitmask Gotcha

One of the most dangerous traps in Windows scripting is assuming that an exit code greater than `0` signifies an error. `robocopy.exe` returns a **bitmap exit code** where values from `0` through `7` indicate various degrees of operational **success**:

| Exit Code | Meaning | Severity |
| :--- | :--- | :--- |
| `0` | No files were copied (source and destination are completely in sync). | **Success** |
| `1` | One or more files were successfully copied. | **Success** |
| `2` | Extra files or directories were detected in the destination. | **Success** |
| `3` | Files were copied AND extra files exist (`1 + 2`). | **Success** |
| `4` | Mismatched files were detected. | **Success** |
| `5` | Files copied AND mismatches exist (`1 + 4`). | **Success** |
| `6` | Extra files detected AND mismatches exist (`2 + 4`). | **Success** |
| `7` | Files copied, extra files present, AND mismatches exist (`1 + 2 + 4`). | **Success** |
| `8` | Some files or directories could not be copied (access denied / file in use). | **Failure** |
| `16` | Fatal error: Invalid arguments, missing source directory, or drive offline. | **Fatal Error** |

### Robust Robocopy Evaluation

```bat
robocopy "C:\Source" "D:\Backup" /e /r:2 /w:5 /log:"backup.log"

:: Check if code is 8 or greater (Actual Failure)
if %ERRORLEVEL% GEQ 8 (
    echo [ERROR] Robocopy encountered critical errors: %ERRORLEVEL%
    exit /b %ERRORLEVEL%
) else (
    echo [SUCCESS] Backup completed cleanly (Robocopy code: %ERRORLEVEL%).
)
```

---

## 3. Core System32 Exit Code Standards

Common Windows administrative utilities report distinct exit patterns:

| Utility | Success | Failure / Details |
| :--- | :--- | :--- |
| `ping.exe` | `0` (Reply received) | `1` (Request timed out / destination host unreachable) |
| `sc.exe` | `0` (Command accepted) | `1060` (Service does not exist), `1056` (Already running), `5` (Access Denied) |
| `net.exe` | `0` (Operation succeeded) | `2` (User/group not found), `5` (Access Denied) |
| `reg.exe` | `0` (Key/value read or written) | `1` (Key/value not found or access denied) |
| `schtasks.exe` | `0` (Task queried/run/created) | `1` (Task not found or access denied) |
| `findstr.exe` | `0` (Pattern matched in stream) | `1` (Pattern not found), `2` (File error / syntax error) |

---

## 4. Conditional Chaining (`&&` vs. `||`)

Use short-circuit operators to handle simple validation without writing multi-line `if` statements:

```bat
:: Stop service and log failure immediately if command fails
net stop "Spooler" >nul 2>&1 || (
    echo [ERROR] Failed to stop Print Spooler service! >> "error.log"
    exit /b 1
)

:: Test directory existence or create it
if not exist "C:\Staging" (
    mkdir "C:\Staging" 2>nul || (
        echo [ERROR] Failed to create C:\Staging directory!
        exit /b 1
    )
)
```

---

## 5. Simulating Try / Catch in Batch

Batch files can implement structured error interception using subroutines and error traps:

```bat
@echo off
setlocal EnableExtensions EnableDelayedExpansion

call :TryAction :Step1_CreateBackup
if !ERRORLEVEL! NEQ 0 goto :FailureHandler

call :TryAction :Step2_DeployConfig
if !ERRORLEVEL! NEQ 0 goto :FailureHandler

echo [SUCCESS] All deployment steps executed without error.
exit /b 0

:: ============================================================================
:: Try Runner Subroutine
:: ============================================================================
:TryAction
set "ACTION_LABEL=%~1"
echo [*] Executing %ACTION_LABEL%...
call %ACTION_LABEL%
set "STEP_RESULT=!ERRORLEVEL!"
if !STEP_RESULT! NEQ 0 (
    echo [FAIL] %ACTION_LABEL% exited with code !STEP_RESULT!
    exit /b !STEP_RESULT!
)
exit /b 0

:Step1_CreateBackup
xcopy /y /q "C:\App\app.conf" "C:\App\app.conf.bak" >nul 2>&1
exit /b %ERRORLEVEL%

:Step2_DeployConfig
copy /y "C:\Staging\app.conf" "C:\App\app.conf" >nul 2>&1
exit /b %ERRORLEVEL%

:FailureHandler
echo [ABORT] Rolling back changes due to step failure...
if exist "C:\App\app.conf.bak" copy /y "C:\App\app.conf.bak" "C:\App\app.conf" >nul 2>&1
endlocal & exit /b 1
```
