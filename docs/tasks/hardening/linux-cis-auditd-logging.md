---
title: Linux CIS Benchmark — Comprehensive Auditd & Telemetry Baseline
type: workflow
platforms:
  - Linux
languages:
  - Bash
tasks:
  - Hardening
  - Detection Engineering
  - Forensics
verified: true
last_verified: 2026-10-08
difficulty: advanced
tags:
  - cis-benchmark
  - auditd
  - audit-rules
  - telemetry
  - immutable-logging
  - syscalls
---

# Linux CIS Benchmark — Comprehensive Auditd & Telemetry Baseline

The Linux Kernel Audit Subsystem (`auditd`) provides foundational, tamper-resistant system telemetry for intrusion detection and forensics. **CIS Section 4 (Logging and Auditing)** requires configuring exact kernel syscall auditing rules and locking the configuration with an **immutable flag (`-e 2`)** to prevent attackers from disabling logging even with root access.

---

## 1. Audit Subsystem Architecture & Daemon Configuration

`auditd` intercepts system calls directly inside the Linux kernel (`kauditd`) and serializes records into `/var/log/audit/audit.log`.

```mermaid
graph TD
    User[User / Process Action] --> Kernel[Linux Kernel Syscall Interface]
    Kernel --> Kaudit[kauditd Kernel Filter Engine]
    Kaudit --> Rules{Rules in 99-cis.rules}
    Rules -- Matched --> Netlink[Netlink Socket]
    Netlink --> Daemon[auditd User Daemon]
    Daemon --> Disk[/var/log/audit/audit.log]
    Daemon --> Syslog[audisp-syslog / Rsyslog TLS Forwarder]
```

### CIS Section 4.1.1: `/etc/audit/auditd.conf` Baseline

Configure the audit daemon to prevent unmonitored log overwriting and enforce alerts on low disk space:

```bash
# Apply hardened auditd.conf directives
sudo tee /etc/audit/auditd.conf << 'EOF'
# CIS Section 4.1.1: Audit Daemon Configuration
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 30
num_logs = 10
priority_boost = 4
name_format = HOSTNAME
max_log_file_action = ROTATE
space_left = 75
space_left_action = EMAIL
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_aupdate = yes
EOF
```

---

## 2. CIS Section 4.1.3: Complete Production Audit Rules (`99-cis.rules`)

Create `/etc/audit/rules.d/99-cis.rules` to audit critical system state changes, file deletions, permission tampering, and identity files:

```bash
sudo tee /etc/audit/rules.d/99-cis.rules << 'EOF'
## -----------------------------------------------------------------------------
## CIS Section 4.1.3: Distribution-Independent Audit Rules Baseline
## -----------------------------------------------------------------------------

# Delete all existing rules
-D

# Set buffer size (prevent packet drop during audit bursts)
-b 8192

# Failure mode: 1 = printk, 2 = kernel panic on critical audit loss
-f 1

## 1. Time & Date Modification (CIS 4.1.4)
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## 2. Identity & Credential Store Modifications (CIS 4.1.5)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## 3. Network Environment Modifications (CIS 4.1.6)
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale

## 4. MAC / DAC Policy Changes (AppArmor / SELinux) (CIS 4.1.7)
-w /etc/apparmor -p wa -k MAC-policy
-w /etc/apparmor.d -p wa -k MAC-policy
-w /etc/selinux -p wa -k MAC-policy

## 5. Discretionary Access Control (DAC) Permission Changes (CIS 4.1.10)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S lchown -S fchownat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

## 6. Unauthorized File Access Attempts (Access Denied) (CIS 4.1.11)
-a always,exit -F arch=b64 -S open -S openat -S creat -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S open -S openat -S creat -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S open -S openat -S creat -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -k access

## 7. Process Execution & Privilege Changes (CIS 4.1.12 & 4.1.13)
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k priv_escalation
-a always,exit -F arch=b32 -S setuid -S setgid -S setreuid -S setregid -k priv_escalation
-w /var/log/sudo.log -p wa -k actions

## 8. Filesystem Mount Operations (CIS 4.1.14)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts

## 9. File Deletion Events by Users (CIS 4.1.15)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete

## 10. Kernel Module Loading and Unloading (CIS 4.1.16)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k modules

## 11. Make Configuration Immutable (CIS 4.1.17)
## MUST BE THE LAST RULE IN THE FILE
-e 2
EOF
```

---

## 3. Applying & Locking Audit Configuration

```bash
# Load rules into the running kernel
sudo augenrules --load

# Verify audit subsystem operational status
sudo auditctl -s

# Verify active rules count
sudo auditctl -l | wc -l
```

> [!CAUTION]
> The `-e 2` flag locks the audit configuration. Once loaded, rules **cannot be altered or cleared** until the server is rebooted, even by the `root` superuser. During initial staging, test rules with `-e 1` before enabling `-e 2` in production.

---

## 4. Operational Investigation Commands (`ausearch` & `aureport`)

Parse structured audit records without raw regex parsing:

```bash
# 1. Investigate unauthorized access attempts (CIS key: access)
sudo ausearch -k access -ts recent

# 2. Investigate identity file changes (/etc/passwd, /etc/shadow)
sudo ausearch -k identity -ts today

# 3. Investigate kernel module loads
sudo ausearch -k modules -ts today

# 4. Generate daily executive summary report
sudo aureport -x --summary
```
