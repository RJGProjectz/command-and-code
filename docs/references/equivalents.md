---
title: Cross-Platform Equivalents
type: reference
platforms: [Windows, Linux, Microsoft Defender, Splunk, SentinelOne]
languages: [PowerShell, Bash, KQL, SPL, S1QL]
tasks: [Investigation, Incident Response, Threat Hunting, Administration]
category: Reference
tags: [equivalents, cheat sheet, windows vs linux, kql vs spl, translation]
aliases: [linux equivalent of, powershell equivalent of, kql to spl, spl to kql, windows linux command comparison]
verified: true
last_verified: 2026-10-05
search:
  boost: 2
---

# Cross-Platform Equivalents

The same question asked on each platform. Follow the links for options, output interpretation and caveats. Equivalence is approximate where platforms differ — each row notes what the telemetry approach actually sees.

## Endpoint commands: Windows ↔ Linux

| Task | Windows (PowerShell / CLI) | Linux (Bash) |
| --- | --- | --- |
| OS and build | `Get-CimInstance Win32_OperatingSystem` | `cat /etc/os-release; uname -r` |
| Uptime / last boot | `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` | `uptime; who -b` |
| [Listening ports](../platforms/windows/networking.md#find-listening-ports) | `Get-NetTCPConnection -State Listen` · `netstat -ano` | [`ss -lntup`](../platforms/linux/networking.md#find-listening-ports) |
| Established connections | `Get-NetTCPConnection -State Established` | `ss -tnp state established` |
| DNS lookup | `Resolve-DnsName example.com` | `dig example.com` |
| DNS cache | `Get-DnsClientCache` | `resolvectl show-cache` on recent systemd-resolved versions; most other setups keep no local cache |
| Processes | `Get-Process` · `tasklist` | `ps aux` |
| [Process by PID with command line](../platforms/windows/processes.md#find-a-process-by-pid) | `Get-CimInstance Win32_Process -Filter "ProcessId = 1234"` | [`ps -o pid,ppid,user,cmd -p 1234`](../platforms/linux/processes.md#find-a-process-by-pid) |
| Process tree | [`Get-ProcessTree.ps1`](../toolbox/powershell.md#get-processtree) | `pstree -p -a -s 1234` |
| Kill process | `Stop-Process -Id 1234 -Force` · `taskkill /PID 1234 /F` | `kill -9 1234` |
| Services | `Get-CimInstance Win32_Service` | `systemctl list-units --type=service` |
| Scheduled jobs | `Get-ScheduledTask` · `schtasks /query` | `crontab -l -u USER` · `systemctl list-timers` |
| Autostart locations | Run keys, services, tasks, startup folders | systemd units, cron, shell profiles, `authorized_keys` |
| Users | `Get-LocalUser` | `getent passwd` |
| Admin group members | `Get-LocalGroupMember Administrators` | `getent group sudo wheel` |
| Logged-on users | `query user` | `who` · `w` |
| Logon history | [Security 4624/4625](../platforms/windows/event-logs.md#failed-logons-summary) | [`last`, `lastb`, auth.log](../platforms/linux/logs.md#successful-logins) |
| Read logs | `Get-WinEvent -FilterHashtable @{...}` | `journalctl` · `/var/log/*` |
| File hash | `Get-FileHash -Algorithm SHA256` | `sha256sum` |
| Permissions | `Get-Acl` · `icacls` | `ls -l` · `stat` · `getfacl` |
| Recent files | `Get-ChildItem -Recurse \| Where LastWriteTime -gt ...` | `find / -xdev -mmin -60` |
| Installed software | Uninstall registry keys | `dpkg -l` · `rpm -qa` |
| Firewall rules | `Get-NetFirewallRule` | `nft list ruleset` · `iptables -S` |
| Block an IP | `New-NetFirewallRule -RemoteAddress ... -Action Block` | `iptables -I INPUT -s ... -j DROP` |

## Telemetry queries: KQL ↔ SPL ↔ S1QL

=== "Process creation"

    | Language | Query |
    | --- | --- |
    | KQL | `DeviceProcessEvents \| where FileName =~ "powershell.exe"` |
    | SPL | `index=wineventlog EventCode=4688 NewProcessName="*\\powershell.exe"` |
    | S1QL | `event.type = 'Process Creation' and tgt.process.name = 'powershell.exe'` |

=== "Network connection to IP"

    | Language | Query |
    | --- | --- |
    | KQL | `DeviceNetworkEvents \| where RemoteIP == "203.0.113.10"` |
    | SPL | `\| tstats count FROM datamodel=Network_Traffic WHERE All_Traffic.dest="203.0.113.10" BY All_Traffic.src` |
    | S1QL | `event.type = 'IP Connect' and dst.ip.address = '203.0.113.10'` |

=== "Failed logons"

    | Language | Query |
    | --- | --- |
    | KQL | `DeviceLogonEvents \| where ActionType == "LogonFailed"` |
    | SPL | `index=wineventlog EventCode=4625` |
    | S1QL | `event.type = 'Login' and event.login.loginIsSuccessful = false` |

=== "Run key writes"

    | Language | Query |
    | --- | --- |
    | KQL | `DeviceRegistryEvents \| where RegistryKey has @"\CurrentVersion\Run"` |
    | SPL | `index=wineventlog source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\CurrentVersion\\Run*"` |
    | S1QL | `event.type = 'Registry Value Modified' and registry.keyPath contains:anycase '\\CurrentVersion\\Run'` |

## Query-language building blocks

| Concept | KQL | SPL | S1QL / PowerQuery |
| --- | --- | --- | --- |
| Time range | `where Timestamp > ago(24h)` | `earliest=-24h` | console time picker |
| Equals (case-insensitive) | `=~` | `field=value` (case-insensitive by default) | `in:anycase (...)` |
| Substring | `contains`, `has` | `field="*value*"` | `contains`, `contains:anycase` |
| Regex | `matches regex` | `\| regex field="..."` | `matches` |
| Count by | `summarize count() by X` | `stats count BY X` | `\| group n = count() by X` |
| Distinct count | `dcount(X)` | `dc(X)` | `estimate_distinct(X)` |
| Choose columns | `project` | `table` / `fields` | `\| columns` |
| Sort | `order by X desc` | `sort - X` | `\| sort -X` |
| Limit | `take 100` | `head 100` | `\| limit 100` |

S1QL rows are [unverified](../detection/s1ql/index.md) until tested in your console. SPL rows depend on your add-on field names.

## Related

- [KQL fundamentals](../detection/kql/fundamentals.md)
- [SPL fundamentals](../detection/spl/fundamentals.md)
- [S1QL fundamentals](../detection/s1ql/fundamentals.md)
