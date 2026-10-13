---
title: Fundamentals — Virtual Memory, Paging, Stack & Heap
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Forensics
  - Investigation
verified: true
last_verified: 2026-10-12
difficulty: advanced
tags:
  - memory
  - virtual-memory
  - heap
  - stack
---

# Fundamentals — Virtual Memory, Paging, Stack & Heap

Modern OS kernels isolate process execution through memory virtualization, translating virtual addresses to physical RAM via page tables.

Each process sees its own private address space. The CPU's memory management unit translates each virtual address to a physical page using page tables maintained by the kernel, and each page carries protection bits (read, write, execute). Those protection bits are what most exploit mitigations and many detections rely on.

## 1. Memory Segments

| Segment | Purpose | Exploitation / Threat Vector |
| :--- | :--- | :--- |
| **Code / Text** | Read-only executable binary instructions | Memory patching (e.g. AMSI and ETW bypasses patch functions in loaded DLLs) |
| **Stack** | Fast, local function variables, call stack frames | Buffer overflows, Return-Oriented Programming (ROP) |
| **Heap** | Dynamically allocated memory (`malloc`, `HeapAlloc`, `VirtualAlloc`) | Heap spray, use-after-free (UAF) |
| **Memory-Mapped Files / Images** | Files and DLLs mapped directly into the address space | Process hollowing, DLL injection, module stomping |

## 2. Exploit Mitigations

- **DEP / NX (Data Execution Prevention / No-Execute)**: Marks stack and heap memory as non-executable.
- **ASLR (Address Space Layout Randomization)**: Randomizes the base addresses of modules in memory to prevent fixed ROP gadget discovery.
- **Stack canaries** (`/GS` on Windows, `-fstack-protector` on Linux): a random value before the return address; a buffer overflow that overwrites it is detected before the function returns.
- **Control Flow Guard (CFG)** / **CET shadow stack**: checks that indirect calls go to valid targets, and that return addresses match a hardware-protected copy, which breaks most ROP chains.

```powershell
# Windows: system-wide and per-program mitigation settings
Get-ProcessMitigation -System
Get-ProcessMitigation -Name chrome.exe
```

```bash
# Linux: ASLR level (2 = full) and protections compiled into a binary
cat /proc/sys/kernel/randomize_va_space
readelf -lW /usr/bin/ssh | grep -E 'GNU_STACK|GNU_RELRO'   # GNU_STACK without E flag = non-executable stack
```

## 3. Why defenders care: in-memory malware

Fileless malware and C2 implants (Cobalt Strike, Sliver, Meterpreter) live only in memory. Their tell-tale signs:

| Indicator | Why it is suspicious |
| --- | --- |
| Private memory that is **read-write-execute (RWX)** | Normal code is read-execute and backed by a file on disk |
| Executable memory **not backed by a file** | Code was written into memory (injection, shellcode) |
| A process whose image on disk differs from what is in memory | Process hollowing |
| Threads starting in unbacked memory | Injected thread (`CreateRemoteThread`, APC injection) |

These checks need a memory capture or live EDR scanning: Volatility 3 `windows.malfind` and `windows.vadinfo`, or PE-sieve / Moneta on a live host.

## Related

- [Windows processes, tokens and handles](windows-processes.md)
- [Malware triage](../../tasks/incident-response/malware-triage.md)
- [AMSI bypass detection (SPL)](../../detection/spl/amsi-bypass.md)

## Sources

- [Microsoft Learn — Memory management (Windows)](https://learn.microsoft.com/windows/win32/memory/memory-management)
- [Microsoft Learn — Exploit protection reference](https://learn.microsoft.com/defender-endpoint/exploit-protection-reference)
- [Linux kernel docs — Memory management](https://docs.kernel.org/admin-guide/mm/index.html)
- [Volatility 3 documentation](https://volatility3.readthedocs.io/)
