---
title: Troubleshooting — High CPU Utilization & Runaway Processes
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Troubleshooting
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - cpu
  - runaway-process
  - perfmon
  - pidstat
  - troubleshooting
---

# Troubleshooting — High CPU Utilization & Runaway Processes

Systematic diagnostic tree and mitigation procedure for isolating runaway processes, thread deadlocks, and kernel/user mode CPU exhaustion across Windows and Linux hosts.

## 1. Diagnostic Decision Tree

```text
[System Alerts: CPU > 90%]
       │
       ▼
Is CPU spent in User Space (%us) or Kernel Space (%sy / Privileged)?
       ├─────────────────────────────────┬─────────────────────────────────┐
       ▼                                 ▼                                 ▼
[High User Time (%us)]         [High System Time (%sy)]        [High I/O Wait (%wa / %D)]
- Application logic loop       - Excessive kernel syscalls     - Disk bottleneck / paging
- Garbage collection storm     - Kernel driver lock contention - Swapping memory pages
- Mining / Cryptojacking       - Hardware interrupt storm      - Check disk queue length
       │                                 │                                 │
       ▼                                 ▼                                 ▼
Identify Top Processes         Audit Interrupts/Drivers        Audit Storage Health
(Get-Process / top / pidstat)  (perf / ETW Kernel Logger)      (iostat / Resource Monitor)
```

## 2. Process & Thread Identification

### Windows (PowerShell & PerfMon)

```powershell
# 1. Identify Top 10 CPU Consumers by CPU time and working set
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id, ProcessName, CPU, WorkingSet64, Path

# 2. Sample realtime processor utilization per process over 5 seconds
Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
    Where-Object { $_.Name -notmatch '_Total|Idle' } |
    Sort-Object PercentProcessorTime -Descending |
    Select-Object -First 5 Name, PercentProcessorTime, IDProcess, CreatingProcessID
```

### Linux (Bash, top & pidstat)

```bash
# 1. Snapshot top processes by instantaneous CPU %
ps -eo pid,ppid,user,%cpu,%mem,comm --sort=-%cpu | head -n 11

# 2. Sample CPU breakdown per thread over 3 intervals
pidstat -u -t 1 3 | head -n 25

# 3. Check for kernel interrupt storms
vmstat 1 5
```

## 3. Operational Remediation & Throttling

### Windows
- **Set Process Priority**:
  ```powershell
  $targetPid = 1234
  (Get-Process -Id $targetPid).PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
  ```
- **Set Processor Affinity** (limit to specific CPU cores):
  ```powershell
  # Restrict process to CPU Core 0 and Core 1 (Affinity mask 0x3)
  $targetPid = 1234
  (Get-Process -Id $targetPid).ProcessorAffinity = 0x3
  ```

### Linux
- **Dynamically Lower Process Priority**:
  ```bash
  TARGET_PID=1234
  renice -n 19 -p "${TARGET_PID}"
  ```
- **Hard Limit CPU Quota via systemd transient scope**:
  ```bash
  TARGET_PID=1234
  systemd-run --scope -p CPUQuota=30% -p MemoryMax=2G kill -STOP "${TARGET_PID}" && kill -CONT "${TARGET_PID}"
  ```
