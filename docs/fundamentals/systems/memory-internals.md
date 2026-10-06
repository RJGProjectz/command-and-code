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
last_verified: 2026-10-06
difficulty: advanced
tags:
  - memory
  - virtual-memory
  - heap
  - stack
---

# Fundamentals — Virtual Memory, Paging, Stack & Heap

Modern OS kernels isolate process execution through memory virtualization, translating virtual addresses to physical RAM via page tables.

## 1. Memory Segments

| Segment | Purpose | Exploitation / Threat Vector |
| :--- | :--- | :--- |
| **Code / Text** | Read-only executable binary instructions | Memory patching / AMSI bypass |
| **Stack** | Fast, local function variables, call stack frames | Buffer overflows, Return-Oriented Programming (ROP) |
| **Heap** | Dynamically allocated memory (`malloc`, `VirtualAlloc`) | Heap spray, use-after-free (UAF) |
| **Memory-Mapped Files** | Files mapped directly to virtual address space | Process hollowing, DLL injection |

---

## 2. Exploit Mitigations

- **DEP / NX (Data Execution Prevention / No-Execute)**: Marks stack and heap memory as non-executable.
- **ASLR (Address Space Layout Randomization)**: Randomizes the base addresses of modules in memory to prevent fixed ROP gadget discovery.
