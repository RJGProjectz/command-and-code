---
title: Knowledge Graph Efficacy & Operational Coverage Matrix
type: reference
platforms:
  - Windows
  - Windows Server
  - Linux
  - Azure
  - Entra ID
  - Microsoft Defender
  - SentinelOne
  - Splunk
languages:
  - PowerShell
  - Bash
  - Python
  - KQL
  - SPL
  - S1QL
  - REST API
tasks:
  - Administration
  - Incident Response
  - Threat Hunting
  - Detection Engineering
  - Hardening
  - Assurance
  - Governance
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - coverage
  - knowledge-graph
  - matrix
  - efficacy
  - audit
  - platforms
  - cross-platform
---

# Knowledge Graph Efficacy & Operational Coverage Matrix

A unified single-pane-of-glass index tracking total operational coverage across platforms, query engines, automation scripts, incident playbooks, REST APIs, and governance frameworks in **Command & Code**.

---

## 1. Executive Knowledge Graph Metrics

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        COMMAND & CODE — COVERAGE DASHBOARD                             │
├───────────────────────────────┬───────────────────────────────┬────────────────────────┤
│ TOTAL DOCUMENTATION NODES     │ 229 Validated Topics          │ 0 Broken Links / Warnings│
│ AUTOMATION SCRIPTS & TOOLS    │ 71 Production Scripts         │ PowerShell, Bash, Python│
│ REST API OPERATIONAL GUIDES   │ 18 API Specifications         │ Graph, Defender, S1... │
│ TELEMETRY QUERY SIGNATURES    │ 40+ Production Queries        │ KQL, SPL, S1QL, Sigma  │
│ INCIDENT RESPONSE PLAYBOOKS   │ 10 End-to-End Playbooks       │ Host, Cloud, Identity  │
│ INVESTIGATION & HUNTING TREES │ 15 Workflows & Decision Trees │ Forensics & Triage     │
│ COMPLIANCE & GRC CROSS-WALKS  │ NIST CSF 2.0, CIS v8, ISO...  │ All 6 NIST Functions   │
└───────────────────────────────┴───────────────────────────────┴────────────────────────┘
```

---

## 2. Cross-Platform Operational Coverage Matrix

Jump directly to any platform's operational capabilities across the entire lifecycle:

| Platform / Technology | Core Administration & OS | Telemetry & Logging | Detections & Queries | Incident Response Playbooks | Hardening & CIS/NIST Baseline | REST API & Automation |
|:---|:---|:---|:---|:---|:---|:---|
| **Windows / Server** | [Processes](../platforms/windows/processes.md) · [Services](../platforms/windows/services.md) · [File Search](../tasks/administration/file-search-discovery.md) | [Event Logs](../platforms/windows/event-logs.md) · [Audit Policy](../platforms/windows/audit-policy.md) · [Sysmon](../fundamentals/systems/sysmon.md) | [Windows Security SPL](../detection/spl/windows-events.md) · [Process KQL](../detection/kql/process-events.md) | [Suspicious PowerShell](../tasks/incident-response/suspicious-powershell.md) · [Ransomware](../tasks/incident-response/ransomware-host-isolation.md) | [Windows Baseline](../tasks/hardening/windows-security-baseline.md) · [WDAC](../platforms/windows/wdac-exploit-guard.md) | [PowerShell Toolbox](../toolbox/powershell.md) · [WinRM/BITS](../tasks/administration/remote-file-transfer.md) |
| **Linux (Ubuntu/RHEL)** | [Systemd](../platforms/linux/systemd.md) · [Storage/LVM](../platforms/linux/storage-lvm.md) · [Remote Transfer](../tasks/administration/remote-file-transfer.md) | [Auditd](../platforms/linux/auditd.md) · [Journal Logs](../platforms/linux/logs.md) | [Linux S1QL Hunting](../detection/s1ql/hunting.md) · [Sigma Rules](../detection/sigma/examples.md) | [Linux Service Failure](../tasks/troubleshooting/linux-service-failure.md) · [Inode Emergency](../tasks/troubleshooting/disk-space-emergency.md) | [Linux Baseline](../tasks/hardening/linux-security-baseline.md) · [Firewalls/nftables](../platforms/linux/firewalls-nftables.md) | [Bash Toolbox](../toolbox/bash.md) · [Defensive Scripting](../languages/bash/defensive-scripting.md) |
| **Microsoft Azure** | [Azure VNet](../fundamentals/cloud/azure-vnet-security.md) · [Azure Policy](../fundamentals/cloud/azure-policy.md) | [Activity Logs](../platforms/microsoft-365/entra.md) · [Log Analytics](../detection/kql/index.md) | [Azure RBAC SPL](../detection/spl/azure-rbac-modification.md) · [Guest Audit](../tasks/assurance/azure-guest-access-audit.md) | [Resource Hijacking](../tasks/incident-response/azure-resource-hijacking.md) · [Automated Containment](../tasks/incident-response/automated-containment.md) | [Azure Security Baseline](../tasks/hardening/cloud-azure-security-baseline.md) · [NSG Compliance](../tasks/assurance/azure-nsg-compliance.md) | [Azure Baseline CLI](../tasks/hardening/cloud-azure-security-baseline.md) · [ServiceNow Webhooks](../apis/webhooks/jira-servicenow-incident-creation.md) |
| **Microsoft Entra ID** | [Entra Fundamentals](../fundamentals/cloud/entra-id-fundamentals.md) · [User Lifecycle](../tasks/administration/user-lifecycle-management.md) | [Signin Logs](../apis/microsoft-graph/sign-in-logs.md) · [Auth Methods](../apis/microsoft-graph/user-auth-methods.md) | [MFA Deletion SPL](../detection/spl/mfa-deletion.md) · [Password Spray KQL](../detection/kql/logon-identity.md) | [Account Compromise](../tasks/incident-response/account-compromise.md) · [Service Principal Compromise](../tasks/incident-response/compromised-service-principal.md) | [Conditional Access](../platforms/microsoft-365/conditional-access.md) · [MFA Enforcement](../tasks/hardening/cloud-azure-security-baseline.md) | [Conditional Access API](../apis/microsoft-graph/conditional-access.md) · [Bearer Auth](../apis/authentication/bearer-tokens.md) |
| **Microsoft Defender** | [Defender Antivirus](../platforms/windows/defender.md) · [EDR Health](../tasks/assurance/endpoint-edr-status.md) | [Advanced Hunting KQL](../detection/kql/fundamentals.md) · [Process Events](../detection/kql/process-events.md) | [Living off the Land KQL](../detection/kql/process-events.md) · [Network Beacons](../detection/kql/network-events.md) | [Endpoint Triage](../tasks/incident-response/endpoint-triage.md) · [Host Isolation](../apis/sentinelone/isolate-host.md) | [ASR Rules](../tasks/hardening/windows-security-baseline.md#3-microsoft-defender-attack-surface-reduction-asr-rules) · [Defender Exclusions](../platforms/windows/defender.md#exclusions) | [Defender Alerts API](../apis/microsoft-defender/get-alerts.md) · [Antivirus Scan API](../apis/microsoft-defender/antivirus-scan.md) |
| **SentinelOne** | [Agent Status](../apis/sentinelone/threats.md) · [Console API](../apis/sentinelone/threats.md) | [Deep Visibility S1QL](../detection/s1ql/fundamentals.md) | [S1QL Hunting Queries](../detection/s1ql/hunting.md) | [Malware Triage](../tasks/incident-response/malware-triage.md) · [Host Disconnect](../apis/sentinelone/isolate-host.md) | [EDR Status Audit](../tasks/assurance/endpoint-edr-status.md) · [Linux EDR](../platforms/linux/antivirus-edr.md) | [S1 Threats API](../apis/sentinelone/threats.md) · [API Bearer Auth](../apis/authentication/bearer-tokens.md) |
| **Splunk SIEM** | [Splunk Search Architecture](../detection/spl/fundamentals.md) · [REST Jobs API](../apis/splunk/management-jobs.md) | [Windows 4624/4625 Events](../detection/spl/windows-events.md) · [DNS Logs](../detection/spl/network-dns.md) | [Brute Force SPL](../detection/spl/brute-force.md) · [SMB Lateral SPL](../detection/spl/lateral-movement-smb.md) | [Suspicious IP Forensics](../tasks/investigation/investigate-ip-splunk.md) · [Host Triage](../tasks/investigation/investigate-device-splunk.md) | [Audit Logging Baseline](../fundamentals/grc/cis-benchmarks.md) | [Splunk Management API](../apis/splunk/management-jobs.md) · [Job Control](../apis/splunk/management-jobs.md) |
| **Web Applications** | [HTTP/S Protocol](../fundamentals/networking/http-https.md) · [Session Management](../fundamentals/web-apps/session-management.md) | [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md) | [OWASP Web Top 10](../fundamentals/web-apps/owasp-web-top-10.md) · [XSS & CSP](../fundamentals/web-apps/xss-defense.md) | [SQLi Parameterization](../fundamentals/web-apps/sql-injection.md) · [SSRF Defense](../fundamentals/web-apps/ssrf-defense.md) | [CSRF Defense](../fundamentals/web-apps/csrf-defense.md) · [Cookie Security](../fundamentals/web-apps/session-management.md) | [REST API Architecture](../fundamentals/apis/rest-architecture.md) · [Rate Limiting](../fundamentals/apis/rate-limiting-backoff.md) |

---

## 3. Coverage by Security Governance Framework

### NIST Cybersecurity Framework (CSF) 2.0 Mapping

```text
┌─────────────────┬──────────────────────────────────────────────────────────────────────┐
│ NIST FUNCTION   │ COVERAGE IN COMMAND & CODE                                           │
├─────────────────┼──────────────────────────────────────────────────────────────────────┤
│ 1. GOVERN (GV)  │ GRC Cross-Walk, CIS Controls v8, Azure Governance & Policy Baselines │
│ 2. IDENTIFY (ID)│ Asset Inventory, Endpoint Triage, AD Audit, Software Vulnerabilities │
│ 3. PROTECT (PR) │ Windows & Linux Baselines, ASLR, ASR Rules, LSA Protection, MFA, PKI │
│ 4. DETECT (DE)  │ KQL, SPL, S1QL & Sigma catalogs, Process/Network/Registry telemetry  │
│ 5. RESPOND (RS) │ 10 Incident Response Playbooks, Host Isolation, Token Revocation     │
│ 6. RECOVER (RC) │ Backup & Recovery Operations, BitLocker Key Recovery, System Updates │
└─────────────────┴──────────────────────────────────────────────────────────────────────┘
```

### CIS Controls v8 Coverage (Implementation Groups IG1, IG2, IG3)

- **Control 01 (Inventory & Control of Enterprise Assets):** Windows CIM inventory, Linux `lshw`, Defender/S1 reconciliation (`FUNC_PS_COMPARE_DEFENDER_S1_INVENTORY.ps1`).
- **Control 03 (Data Protection):** BitLocker Key Recovery, Azure Storage HTTPS/TLS 1.2 enforcement, Key Vault Purge Protection.
- **Control 04 (Secure Configuration of Enterprise Assets & Software):** Hardened Windows & Linux Security Baselines, sysctl runtime tuning, SSH daemon hardening.
- **Control 05 (Account Management):** Active Directory & Entra ID User Lifecycle Management, Inactive Account cleanup (`FUNC_PS_GET_INACTIVE_USERS.ps1`).
- **Control 06 (Access Control Management):** Multi-Factor Authentication enforcement, Conditional Access baseline, Sudoers integrity auditing.
- **Control 08 (Audit Log Management):** Advanced Process Auditing (4688 with cmdline), PowerShell Script Block Logging (4104), Linux Auditd rules.
- **Control 10 (Malware Defenses):** Microsoft Defender Antivirus management, ASR Rules in Block Mode, Linux EDR agent status.
- **Control 17 (Incident Management):** 10 Incident Response Playbooks, Automated Containment Runbook, Slack/Teams/Jira incident dispatch webhooks.
