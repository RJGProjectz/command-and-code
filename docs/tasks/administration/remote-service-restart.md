---
title: Administration — Remote Service Restart & Dependency Validation
type: workflow
platforms:
  - Windows Server
  - Windows
languages:
  - PowerShell
  - CMD
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - administration
  - services
  - maintenance
  - restart
---

# Administration — Remote Service Restart & Dependency Validation

Safe procedure to inspect, stop, and restart unresponsive Windows services across remote servers while checking dependent services.

---

## 1. PowerShell Safe Service Restart

```powershell
param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][string]$ServiceName
)

$Service = Get-Service -ComputerName $ComputerName -Name $ServiceName -ErrorAction Stop
Write-Host "[*] Service $($Service.Name) is currently $($Service.Status)"

# Check dependent services before stopping
if ($Service.DependentServices) {
    Write-Warning "Dependent services will also be affected: $(($Service.DependentServices.Name) -join ', ')"
}

Restart-Service -InputObject $Service -Force -Verbose
```

---

## 2. Windows CMD Operations

### Remote Service Diagnostics (`sc.exe`)
Query running state and enumerate dependencies over standard RPC / SMB named pipes:

```bat
:: Query running state of remote service
sc.exe \\WIN-SRV01 query "W3SVC"

:: Inspect service binary path, user context, and startup configuration
sc.exe \\WIN-SRV01 qc "W3SVC"

:: Enumerate dependent services that rely on this service
sc.exe \\WIN-SRV01 enumdepend "W3SVC"
```

### Remote Service Restart Sequence
Stop the target service, verify termination, and start it cleanly:

```bat
:: 1. Issue stop command
sc.exe \\WIN-SRV01 stop "W3SVC"

:: 2. Verify service reached STOPPED state
sc.exe \\WIN-SRV01 query "W3SVC" | findstr /i "STOPPED"

:: 3. Issue start command
sc.exe \\WIN-SRV01 start "W3SVC"
```

### Automated Restart Batch Script with Polling Loop

```bat
@echo off
setlocal EnableDelayedExpansion

set "SERVER=%~1"
set "SERVICE=%~2"

if "%SERVER%"=="" (
    echo Usage: restart-service.cmd ^<server^> ^<service^>
    exit /b 1
)

echo [*] Inspecting %SERVICE% on %SERVER%...
sc.exe \\%SERVER% query "%SERVICE%" | findstr /i "STATE"

echo [*] Issuing STOP command...
sc.exe \\%SERVER% stop "%SERVICE%" >nul 2>&1

:: Poll until stopped (up to 10 seconds)
for /l %%i in (1,1,10) do (
    sc.exe \\%SERVER% query "%SERVICE%" | findstr /i "STOPPED" >nul && goto :ServiceStopped
    timeout /t 1 /nobreak >nul
)
:ServiceStopped

echo [*] Issuing START command...
sc.exe \\%SERVER% start "%SERVICE%" >nul 2>&1

:: Poll until running
for /l %%i in (1,1,10) do (
    sc.exe \\%SERVER% query "%SERVICE%" | findstr /i "RUNNING" >nul && (
        echo [OK] Service %SERVICE% successfully started on %SERVER%.
        exit /b 0
    )
    timeout /t 1 /nobreak >nul
)

echo [WARNING] Service restart timed out or is in START_PENDING.
exit /b 1
```
