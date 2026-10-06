---
title: Verb the Thing                      # e.g. "Find Listening TCP Ports" — unique, task-phrased
platforms: [Windows]                       # from tools/vocabulary.yml
languages: [PowerShell]                    # from tools/vocabulary.yml
tasks: [Incident Response, Troubleshooting]
category: Networking                       # one free-text category
security_domain: Network                    # Identity | Endpoint | Network | Cloud | Application | Operations | Governance | Intelligence
author: RJGProjectz
date_created: 2026-10-06
last_updated: 2026-10-06
tags: [tag-one, tag-two]
aliases: [other phrase people search for, command name]
difficulty: basic                          # basic | intermediate | advanced
verified: false                            # set true only after checking against vendor docs / testing
# last_verified: 2026-10-06                # required when verified: true
---

# Verb the Thing
> **Created**: 2026-10-06T02:45:00Z
> **Last Modified**: 2026-10-06T02:45:00Z
> **Author**: RJGProjectz

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This article contains technical commands. Before running any script:
> 1. Ensure you are in a `Test` or `Dev` environment.
> 2. Validate commands with `-WhatIf` / `--whatif` where supported.
> 3. Never run unverified commands directly in production.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

One or two sentences: what this answers and why an analyst or sysadmin needs it.

<!-- =========================================================================
     OPERATIONAL METHODOLOGY BLUEPRINT (FOR SERVICES, DAEMONS & PROTOCOLS):
     For any service, daemon, or operational component (e.g. SSH, Nginx, Cron,
     SMB, DNS, Systemd, AD), always present information in this beginner-friendly,
     systematic progression:

     1. Check Process, Service & Socket State (Is it running? PID? Listening port?)
     2. Known Locations & Key Filesystem Paths (Where do binaries, configs, and logs live?)
     3. Configuration Inspection & Syntax Testing (Live runtime config & pre-flight syntax check)
     4. Operational Diagnostics & Key/Session Inspection (Who is connected? Keys, active state)
     5. Hardening, Remediation & Advanced Operations (Security baseline, safe reload, client debug)
     ========================================================================= -->

## 1. Check Process, Service & Socket State

Establish whether the target process or daemon is actively running and identify its listening interfaces/ports:

```powershell
# Check service status and process state
Get-Service -Name '<ServiceName>'
Get-CimInstance Win32_Service -Filter "Name = '<ServiceName>'" | Select-Object Name, State, StartMode, ProcessId

# Verify listening network ports and sockets
Get-NetTCPConnection -State Listen | Where-Object LocalPort -eq 443
```

*(Linux equivalent: `systemctl status <service>`, `pgrep -a <process>`, `sudo ss -tulpn | grep ':<port>\b'`)*

## 2. Known Locations & Key Filesystem Paths

Reference table of critical filesystem locations (binaries, config directories, drop-ins, and log targets):

| Component | Standard Path | Purpose / Description |
| :--- | :--- | :--- |
| **Daemon Binary** | `C:\Path\To\binary.exe` or `/usr/sbin/daemon` | Primary executable |
| **Configuration** | `C:\ProgramData\App\config.json` or `/etc/app/config.conf` | Active configuration |
| **Config Drop-ins** | `/etc/app/conf.d/*.conf` | Modular configuration overrides |
| **Log Targets** | Event Log / `/var/log/app/` | Service execution and audit logs |

## 3. Configuration Inspection & Syntax Testing

Inspect effective configuration settings and test syntax prior to restarting:

```powershell
# Inspect active configuration
Get-Content -Path 'C:\Path\To\config.json'
```

*(Linux equivalent: `sudo <daemon> -T` for live config, `sudo <daemon> -t` or `configtest` for syntax check)*

## 4. Operational Diagnostics & Component Inspection

Perform component-specific audits (keys, certificates, active user sessions, execution logs):

```powershell
# Audit active sessions, connections, or recent log entries
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4624 } -MaxEvents 10
```

## 5. Hardening Baseline & Safe Maintenance

Production hardening rules and safe reload/restart procedures that avoid dropping active connections.

=== "GUI"

    ```text
    Settings → Area → Page
    ```

=== "PowerShell"

    ```powershell
    Get-Setting
    ```

=== "Registry"

    ```text
    HKLM\SOFTWARE\Vendor\Key   ValueName (DWORD) = 1
    ```

=== "GPO"

    ```text
    Computer Configuration → Administrative Templates → …
    ```

## Notes

Version differences, permissions required, performance caveats, false positives.

## Related

- [Linux equivalent](../linux/page.md)
- [Workflow that uses this](../../tasks/incident-response/workflow.md)
- [Detection query](../../detection/kql/page.md)

## External Resources & White Papers

- [Official documentation title](https://learn.microsoft.com/...)
