---
title: Investigation Playbook — SMB Lateral Movement
type: workflow
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - SPL
tasks:
  - Incident Response
  - Threat Hunting
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - playbook
  - smb
  - lateral-movement
  - psexec
---

# Investigation Playbook — SMB Lateral Movement

Operational hunting and response procedure for lateral movement using SMB (Port 445), administrative shares (`ADMIN$`, `C$`, `IPC$`), and remote service installation (e.g. PsExec, Impacket).

---

## 1. Objective & Scope

- **What is being investigated**: Adversaries hopping between internal workstations and servers using SMB file transfers and RPC named pipes.
- **Why it matters**: SMB lateral movement (MITRE ATT&CK [T1021.002](https://attack.mitre.org/techniques/T1021/002/)) is the primary vector for enterprise-wide ransomware staging and domain escalation.

---

## 2. Telemetry Queries

### Splunk — Remote Service Installation (Event ID 7045)

```spl
index=win_logs EventCode=7045
| eval ServiceFile = Service_File_Name
| search ServiceFile="*\\ADMIN$\*" OR ServiceFile="*\\C$\*" OR ServiceFile="*psexec*" OR ServiceFile="*.bat*"
| table _time, ComputerName, Service_Name, ServiceFile, Service_Type, User
```

### PowerShell Live Inspection — Active SMB Sessions

```powershell
# Inspect active incoming SMB connections and open files
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens, SecondsExists
Get-SmbOpenFile | Select-Object FileId, Path, ClientComputerName, ClientUserName
```

---

## 3. Containment & Remediation

1. **Host Isolation**: Sever network access on both source and destination machines.
2. **Reset Compromised Credentials**: Immediately force password reset and Kerberos ticket revocation for the identity found in `ClientUserName`.
3. **Inspect Dropped Service Binaries**: Extract hash from `Service_File_Name` path and submit to VirusTotal/EDR telemetry.
