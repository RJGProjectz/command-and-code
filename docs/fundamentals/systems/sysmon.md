---
title: Fundamentals — Sysmon Telemetry & Endpoint Monitoring
type: entry
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Threat Hunting
  - Detection Engineering
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - sysmon
  - telemetry
  - threat-hunting
  - detection
---

# Fundamentals — Sysmon Telemetry & Endpoint Monitoring

System Monitor (Sysmon) installs as a device driver and service to log deep endpoint telemetry into the Windows Event Log or Linux syslog.

## Essential Sysmon Event IDs

| Event ID | Name | Forensic / Detection Value |
| :--- | :--- | :--- |
| **Event 1** | Process Creation | Full command lines, parent image, hash, current directory |
| **Event 3** | Network Connection | Outbound sockets linked to originating process binary |
| **Event 7** | Image Loaded | DLL loads, tracking DLL side-loading and injection |
| **Event 8** | CreateRemoteThread | Process injection (mimikatz, cobalt strike beacons) |
| **Event 10** | ProcessAccess | LSASS memory handle access (`0x10` PROCESS_VM_READ) |
| **Event 11** | FileCreate | Dropped malware, payloads, and staging files |
| **Event 12/13/14** | Registry Events | Persistence keys (`Run`, `RunOnce`, services, Winlogon) |
| **Event 22** | DNSEvent | Per-process DNS queries and return answers |
