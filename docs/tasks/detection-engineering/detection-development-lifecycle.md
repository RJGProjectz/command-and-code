---
title: Detection Development Lifecycle (DDLC) and Testing
type: workflow
platforms:
  - Windows
  - Linux
  - Microsoft Defender
  - Splunk
  - SentinelOne
languages:
  - KQL
  - SPL
  - S1QL
  - Sigma
  - PowerShell
tasks:
  - Detection Engineering
  - Threat Hunting
  - Incident Response
verified: true
last_verified: 2026-10-07
difficulty: intermediate
tags:
  - detection-engineering
  - ddlc
  - atomic-red-team
  - continuous-testing
  - detection-as-code
  - ci-cd
---

# Detection Development Lifecycle (DDLC) and Testing

A structured Detection Development Lifecycle ($DDLC$) ensures analytics provide high-fidelity alert signals, withstand adversary evasion, and transition cleanly into production SIEM/EDR platforms without overwhelming SOC analysts with alert fatigue.

---

## 1. The 6-Stage Detection Engineering Pipeline

```text
[1. Threat Modeling & Scope]
       ↓ (MITRE ATT&CK technique, adversary emulation, target telemetry)
[2. Telemetry Audit & Prerequisites]
       ↓ (Event ID 4688 with CLI, Sysmon Event 1, EDR sensor enabled)
[3. Query Hypothesis & Construction]
       ↓ (KQL / SPL / S1QL query draft, field normalization, thresholds)
[4. Adversary Emulation & Validation]
       ↓ (Atomic Red Team test execution, log validation, detection firing)
[5. False Positive Baselining & Tuning]
       ↓ (Historical query testing against 30-day production log baseline)
[6. Deployment & CI/CD Detection-as-Code]
       ↓ (Git pull request, unit testing, automated push to SIEM/EDR)
[Active Monitoring & Drift Review]
```

---

## 2. Telemetry Auditing & Data Source Prerequisites

Before writing a detection rule, verify that endpoints are logging the requisite events:

| Detection Target | Required Windows Event | Required Sysmon Event | Required Linux Telemetry |
| :--- | :--- | :--- | :--- |
| **Process Creation** | Event ID 4688 (with Command Line enabled) | Event ID 1 | auditd `execve` / Audit Event |
| **Process Injection / Memory Access** | Event ID 4663 (Handle to Process) | Event ID 10 (`ProcessAccess`) | eBPF `sched_process_exec` |
| **Network Socket Connections** | Windows Filtering Platform (5156/5158) | Event ID 3 (`NetworkConnect`) | auditd `connect` / `bind` |
| **Service Creation** | System Event ID 7045 | Event ID 1 | auditd `systemd` unit writes |
| **Authentication & Logons** | Security Event ID 4624 / 4625 | N/A | `/var/log/auth.log` / `secure` |

---

## 3. Adversary Emulation Testing (Atomic Red Team)

Never deploy a detection rule without executing atomic tests in a staging environment to observe exact telemetry generated:

```powershell
# 1. Install Invoke-AtomicRedTeam runner
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
Install-AtomicRedTeam -getAtomics

# 2. Check prerequisites for an attack technique (e.g. T1059.001 PowerShell)
Invoke-AtomicTest T1059.001 -CheckPrereqs

# 3. Execute atomic test to generate detection telemetry
Invoke-AtomicTest T1059.001 -TestNumbers 1

# 4. Clean up test artifacts after firing
Invoke-AtomicTest T1059.001 -Cleanup
```

---

## 4. Query Construction: Fragile vs. Robust Detections

```text
FRAGILE DETECTION (Easily Evaded):
FileName =~ "mimikatz.exe"
(Attacker renames binary to svchost.exe -> Detection fails completely)

ROBUST BEHAVIORAL DETECTION:
ProcessName =~ "lsass.exe" AND
GrantedAccess in (0x1010, 0x1438, 0x1F0FFF) AND
CallTrace has_any ("dbgcore.dll", "dbghelp.dll")
(Detects memory dumping regardless of binary name or script path)
```

### Example: KQL Detection as Code Specification

```yaml
title: Suspicious Process Injection into LSASS Memory
id: 4a9f2b3e-781c-4b92-91ef-8f4316d8a012
status: production
description: Detects unauthorized processes opening handles with PROCESS_VM_READ access to lsass.exe
author: Command & Code Detection Engineering
references:
  - https://attack.mitre.org/techniques/T1003/001/
severity: high
query: |
  DeviceProcessEvents
  | where ActionType == "OpenProcess"
  | where TargetProcessFileName =~ "lsass.exe"
  | where DesiredAccess in ("0x1010", "0x1438", "0x1F0FFF")
  | where not(InitiatingProcessFileName in~ ("csrss.exe", "svchost.exe", "MsMpEng.exe"))
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, TargetProcessFileName
```

---

## 5. Deployment & Continuous Review Protocol

1. **Test Historical False Positive Ratio**: Run the rule against 30 days of production telemetry. If the alert fires $> 5$ times per day on legitimate administrative activity, it **must not** enter high-severity alerting until refined.
2. **Assign Rule Confidence & SLA**:
   - **High Fidelity (Tier 1)**: Actionable alert triggers automatic host quarantine or immediate SOC pager ($< 15$ min SLA).
   - **Contextual / Correlated (Tier 2)**: Added to risk scoring engine; triggers alert only when accompanied by other signals.
3. **Quarterly Rule Drift Auditing**: Adversaries evolve techniques; software updates introduce new benign baselines. Audit rules every 90 days against current telemetry coverage.
