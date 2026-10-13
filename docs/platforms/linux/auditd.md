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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - linux
  - auditd
  - logging
  - forensics
---

# Linux Audit Daemon (auditd) & Kernel Telemetry

The Linux Audit framework (`auditd`) provides non-bypassable kernel-level logging of system calls, file integrity modifications, and security events.

The kernel generates the events; `auditd` writes them to `/var/log/audit/audit.log`. Rules decide what is recorded, so a host with auditd running but no rules logs little beyond logins and SELinux denials.

## 0. Status

```bash
systemctl is-active auditd
auditctl -s          # enabled (1 = on, 2 = locked), backlog and lost-event counters
auditctl -l          # rules currently loaded in the kernel
```

A rising `lost` counter means events are being dropped: raise the backlog (`-b 8192`) or reduce noisy rules.

## 1. High-Value Audit Rules (`/etc/audit/rules.d/audit.rules`)

```text
# Monitor changes to user accounts and authentication databases
-w /etc/passwd -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Persistence locations
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /root/.ssh/ -p wa -k ssh_keys

# Monitor execution of sensitive privilege-granting binaries
-a always,exit -F path=/usr/bin/sudo -F auid>=1000 -F auid!=4294967295 -k privileged_exec

# Every program started by a real user (high volume: size your log storage)
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k user_exec

# Kernel module loading (rootkits)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k kernel_modules

# Audit configuration itself
-w /etc/audit/ -p wa -k audit_config

# Last line: lock the rules until reboot (an attacker with root cannot remove them quietly)
-e 2
```

Load the rules files and check the result:

```bash
augenrules --load
auditctl -l
```

`-p wa` = write or attribute change. `auid` is the login UID: it stays the same after `sudo` or `su`, so events show *who* logged in, not just `root`. `4294967295` means "not set" (system processes). With `-e 2` set, rule changes need a reboot, so test without it first.

## 2. Searching Audit Logs (`ausearch`)

```bash
# Query audit events flagged with a specific key
ausearch -k sudoers_changes --interpret

# Query all executions by a specific user ID
ausearch -ua 1001 --start today

# Failed events of one type in a time range
ausearch -m USER_LOGIN --success no --start yesterday --end now -i

# Who changed a file
ausearch -f /etc/passwd -i
```

## 3. Reports (`aureport`)

```bash
aureport --summary          # overview of the log
aureport -au --failed -i    # failed authentications
aureport -x --summary       # most-run executables
aureport -k --summary       # events per rule key
```

## 4. Ship it to the SIEM

`audit.log` is local and an attacker with root can delete it. Forward it: audisp `syslog` plugin (`/etc/audit/plugins.d/syslog.conf`, set `active = yes`), or let your agent (Splunk Universal Forwarder `linux:audit`, Elastic Agent, Microsoft Defender for Endpoint) read it.

## Related

- [Linux sudoers integrity check](../../tasks/assurance/linux-sudoers-integrity.md)
- [Scheduled Task and Cron Persistence Review](../../tasks/threat-hunting/scheduled-task-persistence-review.md)
- [Centralized log forwarding (WEF and rsyslog)](../../tasks/administration/centralized-log-forwarding-wef-rsyslog.md)

## Sources

- [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) · [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html) · [ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html) · [aureport(8)](https://man7.org/linux/man-pages/man8/aureport.8.html)
- [Red Hat — Auditing the system (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [linux-audit/audit-userspace — example rules](https://github.com/linux-audit/audit-userspace/tree/master/rules)
