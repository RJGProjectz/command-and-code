---
title: Host Performance and System Resource Auditing
type: workflow
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
  - Python
tasks:
  - Administration
  - Troubleshooting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - performance
  - cpu
  - memory
  - disk-io
  - resource-monitoring
  - psutil
---

# Host Performance and System Resource Auditing

Monitoring real-time CPU consumption, RAM pressure, thread counts, disk I/O bottlenecks, and network throughput across Windows and Linux.

---

## 1. Windows Resource Auditing (PowerShell)

```powershell
# Top 10 processes consuming CPU
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id, ProcessName, CPU, WorkingSet64

# Total physical memory and committed memory utilization
Get-CimInstance Win32_OperatingSystem | Select-Object `
    @{N="TotalGB"; E={[math]::Round($_.TotalVisibleMemorySize/1MB, 2)}}, `
    @{N="FreeGB"; E={[math]::Round($_.FreePhysicalMemory/1MB, 2)}}, `
    @{N="UsedPct"; E={[math]::Round((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/$_.TotalVisibleMemorySize)*100, 1)}}

# Real-time Disk I/O Queue Length and Latency
Get-Counter -Counter "\PhysicalDisk(_Total)\Avg. Disk Queue Length", "\PhysicalDisk(_Total)\Avg. Disk sec/Read" -SampleInterval 2 -MaxSamples 3
```

---

## 2. Linux Resource Auditing (Bash)

```bash
# Real-time virtual memory, page swapping, and context switches
vmstat 1 5

# Disk I/O throughput and utilization per device (%util > 85% indicates bottleneck)
iostat -xz 1 5

# Detailed memory usage in human-readable units
free -h

# Per-process CPU and memory utilization breakdown
pidstat -u -r 1 3
```

---

## 3. Cross-Platform Metrics Ingestion (Python)

```python
import psutil

# CPU utilization percentage across all logical cores
cpu_pct = psutil.cpu_percent(interval=1, percpu=True)
print(f"Per-core CPU Utilization: {cpu_pct}")

# Virtual memory pressure
mem = psutil.virtual_memory()
print(f"Memory: {mem.used / 1e9:.2f} GB used / {mem.total / 1e9:.2f} GB total ({mem.percent}% used)")

# Disk I/O counters
disk_io = psutil.disk_io_counters()
print(f"Disk Read: {disk_io.read_bytes / 1e6:.1f} MB | Write: {disk_io.write_bytes / 1e6:.1f} MB")
```
