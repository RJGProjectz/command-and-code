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

<div class="cc-tree" data-title="High CPU Diagnostic Triage Flow" markdown>

<div class="cc-node cc-node--root" data-id="step-cpu-split" markdown>

#### Step 1: User vs. Kernel Space CPU Triage

Determine whether processor cycles are spent in **User Space** (applications) or **Kernel/System Space** (drivers, interrupts, OS subsystems):

```bash
# Linux: Check instantaneous us (user) vs sy (system) vs wa (io wait)
vmstat 1 5
```
```powershell
# Windows: Check % User Time vs % Privileged Time
Get-Counter '\Processor(_Total)\% User Time', '\Processor(_Total)\% Privileged Time'
```

**Where are the majority of CPU cycles consumed?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-high-user">High User Time (%us > 70%)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-high-system">High System/Kernel Time (%sy > 40%)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-high-iowait">High I/O Wait (%wa / Paging)</button>
</div>

</div>

<div class="cc-node" data-id="step-high-user" markdown>

#### Diagnostic Branch: User Mode Process Spikes

High user time indicates application-level spin loops, runaway threads, compilation, or malicious mining:

```powershell
# Windows: Identify Top 5 CPU processes right now
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Id, ProcessName, CPU, WorkingSet64
```
```bash
# Linux: Identify Top 5 CPU processes
ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 6
```

**Action to take:**
- If legitimate daemon running hot: Throttle priority or pin CPU affinity (see Section 3).
- If unauthorized or suspicious binary: Capture memory dump with `procdump` / `gcore`, then terminate with `taskkill /pid <PID> /f` or `kill -9 <PID>`.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-remediation">Proceed to Throttling</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-high-system" markdown>

#### Diagnostic Branch: Kernel Syscall & Driver Lock Contention

High system/privileged time indicates kernel driver deadlocks, excessive system calls, antivirus driver hooks, or hardware interrupt storms:

```bash
# Linux: Sample system calls per process
pidstat -w 1 3
# Check hardware interrupts
cat /proc/interrupts
```
```powershell
# Windows: Inspect Interrupt and DPC Time
Get-Counter '\Processor(_Total)\% DPC Time', '\Processor(_Total)\% Interrupt Time'
```

**Common Root Causes:**
- Antivirus / EDR filter driver scanning storm (e.g. `fltmc.exe` minifilters).
- Failing hardware generating thousands of unhandled hardware interrupts.
- Network driver packet processing bottleneck.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-high-iowait" markdown>

#### Diagnostic Branch: Storage Bottleneck & Memory Swapping

High I/O wait means CPU is idling while waiting for disk operations or thrashing memory pages:

```bash
# Linux: Check disk throughput and queue size
iostat -xz 1 3
# Check swap usage
free -h
```
```powershell
# Windows: Check disk queue length and pages/sec
Get-Counter '\PhysicalDisk(_Total)\Current Disk Queue Length', '\Memory\Pages/sec'
```

If memory is exhausted, the OS continuously swaps pages to disk, pinning storage queues and causing CPU wait spikes.

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-remediation" markdown>

#### Immediate Process Throttling & Priority Mitigation

Safely throttle runaway processes without causing service crashes:

```powershell
# Windows: Lower process priority class
$TargetPid = '<PID>'
$TargetProcess = Get-Process -Id $TargetPid
$TargetProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal

# Windows: Restrict process to CPU Core 0 and Core 1 (Affinity mask 0x3)
$TargetProcess.ProcessorAffinity = 0x3
```
```bash
# Linux: Renice process to lower priority (+10)
renice +10 -p '<PID>'

# Linux: Restrict process to CPU cores 0 and 1
taskset -cp 0,1 '<PID>'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

</div>

---

## 1. Classical Overview Architecture

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
