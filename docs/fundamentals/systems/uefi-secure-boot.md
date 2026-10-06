---
title: Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Hardening
  - Assurance
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - uefi
  - secure-boot
  - tpm
  - bootkits
---

# Fundamentals — UEFI Boot Sequence & Secure Boot Mechanics

Unified Extensible Firmware Interface (UEFI) and Secure Boot prevent rootkits and bootkits by validating the cryptographic signature of every bootloader component.

## 1. Boot Sequence Hierarchy

```text
[Power On] ──► [UEFI Firmware Initialized]
                      │
           (Verifies Signature against KEK / DB)
                      ▼
[Shim / Windows Boot Manager (bootmgfw.efi)]
                      │
           (Verifies Kernel Signature)
                      ▼
[OS Kernel (ntoskrnl.exe / vmlinuz)] ──► [Early Launch Anti-Malware (ELAM)] ──► [OS Drivers]
```

## 2. Hardware Root of Trust: TPM 2.0

Trusted Platform Module (TPM) measures boot integrity into Platform Configuration Registers (PCRs). If firmware or bootloader files are modified, PCR hashes change, preventing BitLocker key unsealing.
