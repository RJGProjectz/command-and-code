---
title: MITRE ATT&CK® Enterprise Matrix & Navigator Coverage
type: reference
platforms:
  - Windows
  - Linux
  - Azure
  - Entra ID
  - Microsoft Defender
  - SentinelOne
  - Splunk
languages:
  - KQL
  - SPL
  - S1QL
  - PowerShell
  - Bash
tasks:
  - Detection Engineering
  - Incident Response
  - Threat Hunting
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - mitre-attack
  - tactics
  - techniques
  - navigator
  - coverage
---

# MITRE ATT&CK® Enterprise Matrix & Navigator Coverage

A verifiable cross-walk indexing all adversary techniques, tactics, detection signatures, and response playbooks in **Command & Code** mapped against the **MITRE ATT&CK® Enterprise Taxonomy (v15)**.

---

## 1. Executive Matrix Summary

```text
TOTAL VALIDATED TECHNIQUES COVERED : 69 Enterprise Techniques
OFFICIAL NAVIGATOR LAYER ARTIFACT  : site/mitre_attack_coverage.json
TACTIC COVERAGE SPAN               : Initial Access, Execution, Persistence, PrivEsc,
                                     Defense Evasion, Credential Access, Lateral Movement,
                                     Command & Control, Impact, Resource Development
```

> [!TIP]
> **Importing to ATT&CK Navigator:**
> Open [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), select **Open Existing Layer** -> **Upload from local**, and upload `site/mitre_attack_coverage.json` to visualize your team's live operational coverage heatmap.

---

## 2. Technique Coverage by ATT&CK Tactic

| Technique ID | Technique Name | Primary Tactics | Operational Guides & Procedures |
|:---|:---|:---|:---|
| **`T1003`** | OS Credential Dumping | Credential Access | [Detection Development Lifecycle](../tasks/detection-engineering/detection-development-lifecycle.md) |
| **`T1021`** | Remote Services | Lateral Movement | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Smb Lateral Movement](../tasks/incident-response/smb-lateral-movement.md) · [Index](../detection/mitre-attack/index.md) · [Lateral Movement Smb](../detection/spl/lateral-movement-smb.md) |
| **`T1021.001`** | Remote Desktop Protocol | Lateral Movement | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1021.002`** | SMB/Windows Admin Shares | Lateral Movement | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Smb Lateral Movement](../tasks/incident-response/smb-lateral-movement.md) · [Index](../detection/mitre-attack/index.md) · [Lateral Movement Smb](../detection/spl/lateral-movement-smb.md) |
| **`T1027`** | Obfuscated/Encoded Files or Information | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1053`** | Scheduled Task/Job | Execution, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Cron](../platforms/linux/cron.md) · [Systemd](../platforms/linux/systemd.md) · [Scheduled Tasks](../platforms/windows/scheduled-tasks.md) *(+2 more)* |
| **`T1053.003`** | Cron | Execution, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Cron](../platforms/linux/cron.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1053.005`** | Scheduled Task | Execution, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Scheduled Tasks](../platforms/windows/scheduled-tasks.md) · [File Registry Events](../detection/kql/file-registry-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1053.006`** | Systemd Timers | Execution, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Systemd](../platforms/linux/systemd.md) |
| **`T1059`** | Command and Scripting Interpreter | Execution | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1059.001`** | PowerShell | Execution | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Detection Development Lifecycle](../tasks/detection-engineering/detection-development-lifecycle.md) · [Suspicious Powershell](../tasks/incident-response/suspicious-powershell.md) · [Process Events](../detection/kql/process-events.md) *(+1 more)* |
| **`T1059.007`** | JavaScript | Execution | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1068`** | Exploitation for Privilege Escalation | Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Software](../platforms/windows/software.md) |
| **`T1070`** | Indicator Removal | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Files Directories](../platforms/windows/files-directories.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1070.001`** | Clear Windows Event Logs | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1070.006`** | Timestomp | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Files Directories](../platforms/windows/files-directories.md) |
| **`T1071`** | Application Layer Protocol | Command and Control | [Dns](../fundamentals/dns.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Network Events](../detection/kql/network-events.md) · [Index](../detection/mitre-attack/index.md) *(+1 more)* |
| **`T1071.004`** | DNS | Command and Control | [Dns](../fundamentals/dns.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Dns Tunneling](../detection/spl/dns-tunneling.md) |
| **`T1078`** | Valid Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Compromised Service Principal](../tasks/incident-response/compromised-service-principal.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1078.004`** | Cloud Accounts | Defense Evasion, Initial Access, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Compromised Service Principal](../tasks/incident-response/compromised-service-principal.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) |
| **`T1098`** | Account Manipulation | Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Ssh](../platforms/linux/ssh.md) · [Entra](../platforms/microsoft-365/entra.md) *(+2 more)* |
| **`T1098.001`** | Additional Cloud Credentials | Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Index](../detection/mitre-attack/index.md) · [Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) |
| **`T1098.004`** | SSH Authorized Keys | Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Ssh](../platforms/linux/ssh.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1098.005`** | Device Registration | Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Entra](../platforms/microsoft-365/entra.md) |
| **`T1105`** | Ingress Tool Transfer | Command and Control | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) |
| **`T1110`** | Brute Force | Credential Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Nist Csf 2](../fundamentals/grc/nist-csf-2.md) · [Logon Identity](../detection/kql/logon-identity.md) · [Index](../detection/mitre-attack/index.md) *(+1 more)* |
| **`T1110.001`** | Password Guessing | Credential Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Brute Force](../detection/spl/brute-force.md) |
| **`T1110.003`** | Password Spraying | Credential Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Logon Identity](../detection/kql/logon-identity.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1134`** | Access Token Manipulation | Defense Evasion, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Windows Processes](../fundamentals/systems/windows-processes.md) |
| **`T1134.004`** | Parent PID Spoofing | Defense Evasion, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Windows Processes](../fundamentals/systems/windows-processes.md) |
| **`T1190`** | Exploit Public-Facing Application | Initial Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1204`** | User Execution | Execution | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) |
| **`T1204.002`** | Malicious File | Execution | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) |
| **`T1218`** | System Binary Proxy Execution | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Process Events](../detection/kql/process-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1219`** | Remote Access Software | Command and Control | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Software](../platforms/windows/software.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1484`** | Domain Policy Modification | Defense Evasion, Privilege Escalation | [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) |
| **`T1484.002`** | Community Technique | Execution | [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) |
| **`T1486`** | Data Encrypted for Impact (Ransomware) | Impact | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Ransomware Host Isolation](../tasks/incident-response/ransomware-host-isolation.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1490`** | Inhibit System Recovery | Impact | [Defense Evasion](../detection/s1ql/defense-evasion.md) |
| **`T1496`** | Resource Hijacking | Impact | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Azure Resource Hijacking](../tasks/incident-response/azure-resource-hijacking.md) |
| **`T1528`** | Steal Application Access Token | Credential Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Entra](../platforms/microsoft-365/entra.md) · [Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) |
| **`T1543`** | Create or Modify System Process | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Systemd](../platforms/linux/systemd.md) · [Services](../platforms/windows/services.md) · [File Registry Events](../detection/kql/file-registry-events.md) *(+1 more)* |
| **`T1543.002`** | Systemd Service | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Systemd](../platforms/linux/systemd.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1543.003`** | Windows Service | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Services](../platforms/windows/services.md) · [File Registry Events](../detection/kql/file-registry-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1546`** | Event Triggered Execution | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Registry](../platforms/windows/registry.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1546.012`** | Image File Execution Options Injection | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Registry](../platforms/windows/registry.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1547`** | Boot or Logon Autostart Execution | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Registry](../platforms/windows/registry.md) · [File Registry Events](../detection/kql/file-registry-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1547.001`** | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Registry](../platforms/windows/registry.md) · [File Registry Events](../detection/kql/file-registry-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1548`** | Abuse Elevation Control Mechanism | Defense Evasion, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Users Permissions](../platforms/linux/users-permissions.md) |
| **`T1548.001`** | Setuid and Setgid | Privilege Escalation, Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Users Permissions](../platforms/linux/users-permissions.md) |
| **`T1555`** | Community Technique | Execution | [Credential Access](../detection/kql/credential-access.md) |
| **`T1556`** | Modify Authentication Process | Credential Access, Defense Evasion, Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) · [Mfa Deletion](../detection/spl/mfa-deletion.md) |
| **`T1556.006`** | Multi-Factor Authentication | Credential Access, Defense Evasion, Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) · [Mfa Deletion](../detection/spl/mfa-deletion.md) |
| **`T1557`** | Adversary-in-the-Middle | Credential Access, Collection | [Dns](../fundamentals/dns.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Dhcp](../fundamentals/networking/dhcp.md) |
| **`T1558`** | Steal or Forge Kerberos Tickets | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Kerberoasting Asreproast Hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1558.001`** | Golden Ticket | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1558.003`** | Kerberoasting | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Kerberoasting Asreproast Hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1558.004`** | AS-REP Roasting | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Kerberoasting Asreproast Hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) |
| **`T1562`** | Impair Defenses | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Defender](../platforms/windows/defender.md) · [Index](../detection/mitre-attack/index.md) · [Agent Tampering](../detection/spl/agent-tampering.md) *(+1 more)* |
| **`T1562.001`** | Disable or Modify Tools | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Defender](../platforms/windows/defender.md) · [Index](../detection/mitre-attack/index.md) · [Agent Tampering](../detection/spl/agent-tampering.md) *(+1 more)* |
| **`T1564`** | Hide Artifacts | Defense Evasion | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Exchange](../platforms/microsoft-365/exchange.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1564.008`** | Email Hiding Rules | Defense Evasion, Persistence | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Exchange](../platforms/microsoft-365/exchange.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1566`** | Phishing | Initial Access | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Phishing Email Triage](../tasks/incident-response/phishing-email-triage.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1574`** | Hijack Execution Flow | Defense Evasion, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Filesystem](../platforms/linux/filesystem.md) · [Services](../platforms/windows/services.md) · [System Information](../platforms/windows/system-information.md) |
| **`T1574.006`** | Dynamic Linker Hijacking (LD_PRELOAD) | Defense Evasion, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Filesystem](../platforms/linux/filesystem.md) |
| **`T1574.007`** | Path Interception by PATH Environment Variable | Defense Evasion, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [System Information](../platforms/windows/system-information.md) |
| **`T1574.009`** | AppCert DLLs | Defense Evasion, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Services](../platforms/windows/services.md) |
| **`T1574.012`** | COR_PROFILER | Defense Evasion, Persistence, Privilege Escalation | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [System Information](../platforms/windows/system-information.md) |
| **`T1584`** | Compromise Infrastructure | Resource Development | [Mitre Attack Matrix](../references/mitre-attack-matrix.md) · [Index](../detection/mitre-attack/index.md) |

---

## 3. Automated Validation & CI Pipeline

This coverage matrix is dynamically maintained by `tools/validate_mitre.py`. Any new detection query, incident response playbook, or hardening configuration tagged with an ATT&CK ID is automatically validated against the enterprise taxonomy during CI verification.
