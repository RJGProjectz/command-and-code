---
title: System32 Native Executables Field Guide
platforms: [Windows, Windows Server]
languages: [CMD, Windows CLI]
tasks: [Administration, Investigation, Troubleshooting, Incident Response]
category: Language
tags: [cmd, system32, windows-cli, netstat, tasklist, sc, reg, wevtutil, netsh, icacls, schtasks, whoami]
aliases: [system32 tools, cmd field manual, native windows tools, tasklist taskkill, sc exe commands, netsh advfirewall]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 2
---

# System32 Native Executables Field Guide

The Windows `System32` directory contains native diagnostic and operational executables that function across all modern Windows desktop and server editions. These binaries operate reliably inside restricted shells, WinPE recovery consoles, and emergency live-response sessions.

---

## 1. Process & Memory Triage

### `tasklist.exe` — Process Enumeration

```bat
:: Standard table listing
tasklist

:: Correlate running processes with hosted Windows Services (svchost triage)
tasklist /svc

:: Verbose output showing window titles and user contexts
tasklist /v

:: Find all processes consuming over 100 MB (102,400 KB) of RAM
tasklist /fi "MEMUSAGE gt 102400"

:: Identify which processes have loaded a specific DLL
tasklist /m ntdll.dll

:: Export processes to CSV format for automated parsing
tasklist /fo csv /nh > C:\Audit\process_snapshot.csv
```

### `taskkill.exe` — Process Termination

```bat
:: Gracefully terminate a process by PID
taskkill /pid 4920

:: Forcefully terminate a process by image name (/f)
taskkill /f /im malicious.exe

:: Forcefully terminate an entire process tree (/t)
taskkill /f /t /im cmd.exe
```

---

## 2. Services Management

### `sc.exe` — Service Controller Engine

```bat
:: Query running status of a service
sc.exe query LanmanServer

:: View detailed service configuration (binary path, startup type, account)
sc.exe qc LanmanServer

:: Configure service startup type (Demand = Manual, Auto = Automatic, Disabled)
:: NOTE: The space after the equal sign is MANDATORY
sc.exe config Spooler start= disabled

:: Query all failed services
sc.exe query state= inactive

:: Stop and start services
sc.exe stop Spooler
sc.exe start Spooler

:: Manage services on a remote Windows host
sc.exe \\WIN-SRV01 query LanmanWorkstation
sc.exe \\WIN-SRV01 stop W3SVC
sc.exe \\WIN-SRV01 start W3SVC
```

---

## 3. Network Architecture & Firewall

### `netstat.exe` — Active Sockets & Ports

```bat
:: Display all listening ports and active TCP/UDP connections with PIDs (-ano)
netstat -ano

:: Correlate listening sockets directly with the executable binary (-b, requires Admin)
netstat -anob

:: Display kernel IP routing table
netstat -r

:: Display per-protocol statistics (TCP, UDP, ICMP)
netstat -s
```

### `netsh.exe` — Firewall & Network Interface Control

```bat
:: Check overall firewall status across Domain, Private, and Public profiles
netsh advfirewall show allprofiles

:: Enable or disable host firewall on all profiles
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles state off

:: Add an inbound rule allowing an administrative service port
netsh advfirewall firewall add rule name="Allow-Syslog-514" dir=in action=allow protocol=UDP localport=514

:: Block all outbound traffic to a specific malicious external IP
netsh advfirewall firewall add rule name="Block-C2-IP" dir=out action=block remoteip=198.51.100.45

:: Display assigned IP configurations across adapters
netsh interface ipv4 show addresses

:: Reset TCP/IP stack and Winsock catalog (reboot required)
netsh int ip reset
netsh winsock reset
```

---

## 4. Scheduled Tasks

### `schtasks.exe` — Job Engine

```bat
:: List all scheduled tasks in verbose list format
schtasks.exe /query /fo list /v

:: Filter tasks for non-Microsoft third-party jobs
schtasks.exe /query /fo table /v | findstr /v /i "Microsoft"

:: Create a scheduled task executing daily as SYSTEM
schtasks.exe /create /tn "DailyAudit" /tr "C:\Audit\audit.cmd" /sc daily /st 02:00 /ru "NT AUTHORITY\SYSTEM"

:: Manually trigger an immediate execution of a scheduled task
schtasks.exe /run /tn "DailyAudit"

:: Forcefully delete a scheduled task
schtasks.exe /delete /tn "DailyAudit" /f
```

---

## 5. Registry Operations

### `reg.exe` — Registry Hive Manipulation

```bat
:: Query Run keys for startup persistence
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

:: Recursive query for a specific value name
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "ImagePath"

:: Add or overwrite a DWORD value (/f forces overwrite without prompt)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f

:: Export a specific registry key to a .reg file for backup
reg export "HKLM\System\CurrentControlSet\Services\LanmanServer" C:\Backup\lanman.reg /y

:: Import a registry backup
reg import C:\Backup\lanman.reg
```

---

## 6. Windows Event Logs

### `wevtutil.exe` — Event Log Engine

```bat
:: List all available event log channels
wevtutil enum-logs

:: Query the 10 most recent Security log events in text format
wevtutil qe Security /c:10 /rd:true /f:text

:: Query specific Event ID (e.g. 4625 Failed Logon) using XPath
wevtutil qe Security "/q:*[System[(EventID=4625)]]" /c:5 /rd:true /f:text

:: Export Security log to an offline .evtx file for external analysis
wevtutil epl Security C:\Forensics\Security_Archive.evtx

:: Clear a log channel (triggers Event ID 1102 / audit log cleared)
wevtutil cl Application
```

---

## 7. Security, Identity & ACLs

### `whoami.exe` — Security Context Discovery

```bat
:: Standard user identity
whoami

:: Comprehensive identity dump: User SID, Group SIDs, and Privileges
whoami /all

:: Inspect assigned privileges only (SeDebugPrivilege, SeImpersonatePrivilege)
whoami /priv

:: Display current user UAC integrity level
whoami /groups | findstr /i "Mandatory Label"
```

### `icacls.exe` & `takeown.exe` — Access Control Lists

```bat
:: View NTFS permissions on a directory
icacls "C:\Audit"

:: Grant Full Control to Administrators and Read/Execute to Users
icacls "C:\Audit" /grant:r "Administrators":(OI)(CI)F "Users":(OI)(CI)RX

:: Remove all inherited permissions and replace with explicit entries
icacls "C:\Audit" /inheritance:r

:: Take ownership of an inaccessible file as Administrator
takeown /f "C:\Windows\System32\drivers\etc\hosts" /a
icacls "C:\Windows\System32\drivers\etc\hosts" /grant "Administrators":F
```

### `auditpol.exe` — Advanced Audit Policy

```bat
:: Display all active audit policies and subcategories
auditpol /get /category:*

:: Audit successful and failed account logon events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

:: Audit process creation (Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable
```

---

## 8. Storage, Cryptography & Maintenance

```bat
:: Query disk free space on drive C:
fsutil volume diskfree C:

:: Verify file SHA-256 hash against known-good baseline
certutil -hashfile "C:\Staging\agent.exe" SHA256

:: Download a file over HTTP/HTTPS natively (EDR staging)
certutil -urlcache -split -f "https://updates.example.com/patch.msu" "C:\Staging\patch.msu"

:: Verify system file integrity against component store
sfc /scannow

:: Repair Windows component store via DISM
dism /online /cleanup-image /restorehealth

:: Force Group Policy update and generate HTML result report
gpupdate /force
gpresult /h C:\Audit\gp_report.html /f
```
