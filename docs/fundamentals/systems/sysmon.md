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
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - sysmon
  - telemetry
  - threat-hunting
  - detection
---

# Fundamentals — Sysmon Telemetry & Endpoint Monitoring

System Monitor (Sysmon) installs as a device driver and service to log deep endpoint telemetry into the Windows Event Log or Linux syslog.

**Why it matters:** default Windows logging does not record full process command lines with hashes, which process opened a network connection, or which process queried which domain. Sysmon adds all of that for free, and most public detection content (Sigma, Splunk ESCU) is written against it. What it logs is decided entirely by its **configuration file**, so the config is the real product.

## Essential Sysmon Event IDs

Events are written to `Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`.

| Event ID | Name | Forensic / Detection Value |
| :--- | :--- | :--- |
| **Event 1** | Process Creation | Full command lines, parent image, hash, current directory |
| **Event 3** | Network Connection | Outbound sockets linked to originating process binary |
| **Event 5** | Process Terminated | Process lifetime (short-lived tools) |
| **Event 6** | Driver Loaded | Vulnerable or malicious drivers (BYOVD) |
| **Event 7** | Image Loaded | DLL loads, tracking DLL side-loading and injection |
| **Event 8** | CreateRemoteThread | Process injection (mimikatz, cobalt strike beacons) |
| **Event 10** | ProcessAccess | LSASS memory handle access (`0x10` PROCESS_VM_READ) |
| **Event 11** | FileCreate | Dropped malware, payloads, and staging files |
| **Event 12/13/14** | Registry Events | Persistence keys (`Run`, `RunOnce`, services, Winlogon) |
| **Event 15** | FileCreateStreamHash | Mark-of-the-Web and other alternate data streams on downloads |
| **Event 17/18** | Pipe Created / Connected | Named pipes used by C2 frameworks and lateral movement |
| **Event 22** | DNSEvent | Per-process DNS queries and return answers |
| **Event 23 / 26** | FileDelete (archived) / FileDeleteDetected | Evidence of deleted tools; 23 keeps a copy |
| **Event 25** | ProcessTampering | Process hollowing and herpaderping |

## Install and update

Download from Microsoft Sysinternals, then start from a maintained community config instead of an empty one: SwiftOnSecurity `sysmon-config` (balanced) or Olaf Hartong `sysmon-modular` (modular, more verbose).

```powershell
# Install with a config (run as administrator)
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml

# Update the config on a running install
.\Sysmon64.exe -c .\sysmonconfig.xml

# Show the active configuration and schema version
.\Sysmon64.exe -c
```

Check that it is running and logging:

```powershell
Get-Service -Name Sysmon64 | Select-Object Status, StartType
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5 | Select-Object TimeCreated, Id
```

## Sysmon for Linux

Sysmon for Linux uses eBPF and writes the same event IDs (for the supported subset) to syslog / the journal:

```bash
sudo sysmon -accepteula -i config.xml
journalctl -t sysmon -n 20
```

## Tuning tips

- Exclude high-volume, known-good noise (your EDR, backup and monitoring agents) by image path **and** signature, not path alone.
- Keep Event 10 (ProcessAccess) targeted at `lsass.exe`; logging all process access floods the log.
- Raise the Sysmon log size (default 64 MB) or forward events quickly; on a busy server 64 MB is a few hours.
- Attackers stop the service or unload the driver (`fltmc unload SysmonDrv`); alert when a host stops sending Sysmon events.

## Related

- [Sysmon deployment and tuning workflow](../../tasks/administration/sysmon-deployment-tuning.md)
- [Windows event logs](../../platforms/windows/event-logs.md)

## Sources

- [Microsoft Sysinternals — Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) · [olafhartong sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [Sysmon for Linux](https://github.com/microsoft/SysmonForLinux)
