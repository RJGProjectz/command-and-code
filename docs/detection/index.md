---
title: Detection
type: index
---

# Detection Engineering

Queries and rules for hunting and detection across the three platforms most security teams live in.

| Language | Platform | Status |
| --- | --- | --- |
| [KQL](kql/index.md) | Microsoft Defender XDR advanced hunting, Microsoft Sentinel | Verified against Microsoft schema documentation |
| [SPL](spl/index.md) | Splunk | Syntax verified; field names environment-dependent |
| [S1QL](s1ql/index.md) | SentinelOne Deep Visibility / PowerQuery | **Unverified** — test in your console |
| [Sigma](sigma/index.md) | Vendor-neutral rules → converted to SPL/KQL | Valid YAML; tune before use |
| [MITRE ATT&CK](mitre-attack/index.md) | Technique mapping for all of the above | — |

## Same question, three query languages

*"Show me PowerShell running encoded commands"*

=== "KQL"

    ```kql
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine matches regex @"(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}"
    ```

=== "SPL"

    ```spl
    index=wineventlog source="XmlWinEventLog:Security" EventCode=4688 NewProcessName="*\\powershell.exe"
    | regex CommandLine="(?i)\s[-/]e[a-z]*\s+[a-z0-9+/=]{20,}"
    ```

=== "S1QL"

    ```text
    event.type = 'Process Creation' and tgt.process.name in:anycase ('powershell.exe', 'pwsh.exe')
    and tgt.process.cmdline contains:anycase ('-enc', '-encodedcommand')
    ```

More side-by-side comparisons: [Cross-platform equivalents](../references/equivalents.md).

## Detection engineering entries

<!-- cc:index tasks="Detection Engineering" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](../tasks/threat-hunting/splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |
| [Fundamentals — Cross-Site Request Forgery (CSRF) & State Defense](../fundamentals/web-apps/csrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Cross-Site Scripting (XSS) & Content Security Policy](../fundamentals/web-apps/xss-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Server-Side Request Forgery (SSRF) & Egress Defense](../fundamentals/web-apps/ssrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — SQL Injection & Parameterized Defense](../fundamentals/web-apps/sql-injection.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [KQL File, Registry and Persistence Hunting](kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Audit Daemon (auditd) & Kernel Telemetry](../platforms/linux/auditd.md) | Entry | Linux | Bash | Forensics, Detection Engineering |
| [S1QL Fundamentals](s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [Sigma Rule Examples](sigma/examples.md) | Entry | Windows | Sigma | Detection Engineering, Threat Hunting |
| [SPL Fundamentals and Search Optimization](spl/fundamentals.md) | Entry | Splunk | SPL | Threat Hunting, Detection Engineering, Investigation |
| [SPL Network and DNS Hunting](spl/network-dns.md) | Entry | Splunk | SPL | Threat Hunting, Investigation, Detection Engineering |
| [SPL PowerShell Hunting](spl/powershell.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Incident Response |
| [SPL Windows Security Events](spl/windows-events.md) | Entry | Splunk, Windows | SPL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Splunk Detection — AMSI Bypass Attempts](spl/amsi-bypass.md) | Entry | Windows, Splunk | SPL, PowerShell | Detection Engineering, Threat Hunting |
| [Splunk Detection — Brute Force Success Correlation](spl/brute-force.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Security Agent Tampering & EDR Impairment](spl/agent-tampering.md) | Entry | Windows, Linux, SentinelOne, Splunk | SPL | Detection Engineering, Incident Response |
| [Splunk Detection — Suspicious Azure RBAC Modification](spl/azure-rbac-modification.md) | Entry | Azure, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious DNS Tunneling Signatures](spl/dns-tunneling.md) | Entry | Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious MFA Authentication Method Deletion](spl/mfa-deletion.md) | Entry | Entra ID, Microsoft 365, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Splunk Detection — Suspicious SMB Administrative Share Access](spl/lateral-movement-smb.md) | Entry | Windows, Windows Server, Splunk | SPL | Detection Engineering, Threat Hunting |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK Mapping](mitre-attack/index.md) | Reference | Windows, Linux, Microsoft 365 | MITRE ATT&CK | Detection Engineering, Threat Hunting, Incident Response |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Windows Event ID Reference](../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |

<!-- /cc:index -->
