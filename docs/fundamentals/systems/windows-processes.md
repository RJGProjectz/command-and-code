---
title: Fundamentals — Windows Process Architecture, Tokens & Handles
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - Windows CLI
tasks:
  - Investigation
  - Forensics
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - windows
  - processes
  - access-tokens
  - handles
---

# Fundamentals — Windows Process Architecture, Tokens & Handles

Every running executable in Windows operates as an isolated process with virtual address space, execution threads, open handles, and an access token.

## 1. Process Access Tokens

An access token contains the security context of the process:
- User SID (Security Identifier) and Group SIDs (e.g. Domain Admins, Everyone).
- Privileges (e.g., `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`).
- Integrity Level: `Untrusted`, `Low`, `Medium` (Standard user), `High` (Elevated Admin), `System`.

---

## 2. Process Lineage & Handle Tables

- **Parent Process ID (PPID)**: Defines the spawning parent. Adversaries use PPID Spoofing ([T1134.004](https://attack.mitre.org/techniques/T1134/004/)) to make malicious binaries appear as children of legitimate processes (e.g., `explorer.exe`).
- **Handles**: Pointers to system objects (files, registry keys, synchronization mutexes, ports).
