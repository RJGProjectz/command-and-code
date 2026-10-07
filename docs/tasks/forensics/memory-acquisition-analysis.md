---
title: Live Memory Acquisition and Volatility Analysis
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
  - Python
tasks:
  - Forensics
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - forensics
  - memory
  - volatility
  - dumpit
  - lime
  - injection
  - triage
---

# Live Memory Acquisition and Volatility Analysis

Volatile physical memory ($RAM$) contains active network sockets, injected code payloads, decrypted credentials, process trees, and rootkit hooks that leave zero traces on disk.

---

## 1. Golden Rules of Volatile Memory Triage

1. **Order of Volatility (RFC 3227)**: RAM evaporates on reboot or power cutoff. Acquire memory **before** running intrusive disk-scanning tools or collecting system logs.
2. **Minimize Footprint**: Every tool executed overwrites pages in RAM. Use statically linked binaries from an external read-only drive (USB or write-blocked network share).
3. **Preserve Pagefile & Hyberfil**: When shutting down a target machine for dead-disk forensics, pull the power cord (desktop) or execute an immediate ACPI hardware cutoff to preserve `hiberfil.sys` and `pagefile.sys`.

---

## 2. Live Memory Acquisition

### Windows: Staging and Acquisition

```powershell
# 1. WinPmem Kernel Acquisition (Statically Linked CLI)
.\winpmem.exe -o C:\Forensics\Triage_Mem\win10_physical_memory.raw

# 2. DumpIt / Comae CLI Execution
.\DumpIt.exe /O C:\Forensics\Triage_Mem\mem_dump.dmp /Q

# 3. Targeted Process Memory Dump (ProcDump - Sysinternals)
# Extract unencrypted memory of a suspicious running process (e.g., lsass.exe or injected svchost)
.\procdump.exe -ma 4920 C:\Forensics\Triage_Mem\process_4920.dmp
```

### Linux: Kernel Module Acquisition (LiME)

```bash
# 1. Check running kernel release for compatible module build
uname -r

# 2. Insert LiME Kernel Module to dump physical memory to raw image
insmod lime-$(uname -r).ko "path=/mnt/forensics/linux_mem.lime format=raw"

# 3. Stream memory over secure netcat if local storage is restricted
# On Forensics Workstation: nc -l -p 4444 > linux_mem.raw
# On Target Host:
insmod lime-$(uname -r).ko "path=tcp:4444 format=raw"
```

---

## 3. Volatility 3 Analysis Recipes

Volatility 3 eliminates the need for manual OS profile selection by dynamically analyzing kernel symbol tables.

```bash
# 1. List active process tree and parentage
python3 vol.py -f win10_physical_memory.raw windows.pslist
python3 vol.py -f win10_physical_memory.raw windows.pstree

# 2. Detect unlinked / hidden processes (Process Hollowing / DKOM)
python3 vol.py -f win10_physical_memory.raw windows.psscan

# 3. Identify injected code and memory hollows (VAD protections: PAGE_EXECUTE_READWRITE)
python3 vol.py -f win10_physical_memory.raw windows.malfind --dump --output-dir /cases/injects/

# 4. Enumerate active and terminated network sockets
python3 vol.py -f win10_physical_memory.raw windows.netscan

# 5. Extract command-line parameters (PowerShell payloads, certutil execution)
python3 vol.py -f win10_physical_memory.raw windows.cmdline

# 6. Extract credentials and cached hashes from memory hives
python3 vol.py -f win10_physical_memory.raw windows.hashdump
python3 vol.py -f win10_physical_memory.raw windows.lsass
```

### Linux Volatility 3 Analysis

```bash
# 1. Enumerate Linux process table
python3 vol.py -f linux_mem.lime linux.pslist

# 2. Check for hidden kernel modules (Rootkits)
python3 vol.py -f linux_mem.lime linux.lsmod

# 3. Socket and network connection triage
python3 vol.py -f linux_mem.lime linux.sockstat

# 4. Check bash history stored in memory
python3 vol.py -f linux_mem.lime linux.bash
```

---

## 4. Operational Troubleshooting & Pitfalls

- **Virtualization & Hypervisors**: If the compromised machine is a virtual machine (Hyper-V, VMware ESXi, Proxmox), **take a live VM snapshot with memory included** via the hypervisor interface instead of injecting memory dump agents into the guest OS. This achieves zero artifact contamination.
- **BitLocker / Full Disk Encryption**: Dumping physical memory captures the cleartext BitLocker master encryption keys (`FVEK`). Use Volatility `windows.bitlocker` to extract keys prior to machine power-off.
