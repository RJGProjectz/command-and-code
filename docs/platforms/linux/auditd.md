---
title: Linux Audit Daemon (auditd) & Kernel Telemetry
type: entry
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Forensics
  - Detection Engineering
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - linux
  - auditd
  - logging
  - forensics
---

# Linux Audit Daemon (auditd) & Kernel Telemetry

The Linux Audit framework (`auditd`) provides non-bypassable kernel-level logging of system calls, file integrity modifications, and security events.

## 1. High-Value Audit Rules (`/etc/audit/rules.d/audit.rules`)

```bash
# Monitor changes to user accounts and authentication databases
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor execution of sensitive privilege-granting binaries
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged_exec
```

## 2. Searching Audit Logs (`ausearch`)

```bash
# Query audit events flagged with a specific key
ausearch -k sudoers_changes --interpret

# Query all executions by a specific user ID
ausearch -ua 1001 --start today
```
