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
| [Administration — Centralized Event Forwarding Pipeline (WEF & Rsyslog TLS)](../tasks/administration/centralized-log-forwarding-wef-rsyslog.md) | Workflow | Windows Server, Windows, Linux | PowerShell, Bash | Administration, Detection Engineering, Hardening, Assurance |
| [Administration — Sysmon Enterprise Deployment & Telemetry Tuning](../tasks/administration/sysmon-deployment-tuning.md) | Workflow | Windows, Windows Server, Linux | PowerShell, Bash | Administration, Detection Engineering, Threat Hunting |
| [Alert Tuning and False Positive Management](../tasks/detection-engineering/alert-tuning-false-positive-management.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL | Detection Engineering, Investigation, Incident Response |
| [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Assurance |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../tasks/threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Cyber Threat Intelligence — STIX 2.1 & TAXII Feed Ingestion Pipeline](../tasks/threat-intelligence/stix-taxii-pipeline.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Threat Hunting |
| [Detection Development Lifecycle (DDLC) and Testing](../tasks/detection-engineering/detection-development-lifecycle.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, Sigma, PowerShell | Detection Engineering, Threat Hunting, Incident Response |
| [Hunting Living-off-the-Land Binaries and Scripts (LOLBins)](../tasks/threat-hunting/lolbins-execution-hunting.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Linux CIS Benchmark — Comprehensive Auditd & Telemetry Baseline](../tasks/hardening/linux-cis-auditd-logging.md) | Workflow | Linux | Bash | Hardening, Detection Engineering, Forensics |
| [Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)](../tasks/threat-hunting/cross-platform-behavioral-hunting.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Hunting — Hypothesis-Driven Methodology & Hunt Lifecycle Framework](../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Incident Response |
| [Threat Hunting — Hypothesis-Driven SIEM Hunting in Splunk](../tasks/threat-hunting/splunk-threat-hunting.md) | Workflow | Splunk, Windows, Linux | SPL | Threat Hunting, Detection Engineering |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../tasks/threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Windows CIS Benchmark — Advanced Audit Policy Baseline](../tasks/hardening/windows-cis-advanced-audit-policy.md) | Workflow | Windows, Windows Server, Active Directory | PowerShell, CMD | Hardening, Detection Engineering, Assurance |
| [Amazon CloudWatch, Logs Insights & Athena](../platforms/aws/monitoring-logs.md) | Entry | AWS | Bash, Python | Investigation, Troubleshooting, Detection Engineering, Administration |
| [AWS Persistence & Threat Hunting](../platforms/aws/persistence-hunting.md) | Entry | AWS | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Azure Monitor & Log Analytics Queries](../platforms/azure/monitoring-logs.md) | Entry | Azure | Bash, PowerShell, KQL | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Azure Persistence & Threat Hunting](../platforms/azure/persistence-hunting.md) | Entry | Azure, Entra ID | KQL, Bash, PowerShell | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [Detection Rule — ARP Spoofing (DAI and arpwatch)](sigma/arp-spoofing-dai.md) | Entry | Linux, Splunk | Sigma, SPL, KQL | Detection Engineering, Threat Hunting |
| [Detection Rule — CI/CD Secret Leak](sigma/cicd-secret-leak.md) | Entry | Splunk | Sigma, SPL, KQL | Detection Engineering, Incident Response |
| [Detection Rule — Cryptomining (Resource Hijacking)](sigma/cryptomining.md) | Entry | Windows, Linux, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Honeytoken and Honey Account Use](sigma/honeytoken-access.md) | Entry | Active Directory, Windows Server, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — LLMNR / NBT-NS Poisoning](sigma/llmnr-nbtns-poisoning.md) | Entry | Windows, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Network Flood (DoS / DDoS)](sigma/dos-flood.md) | Entry | Azure, Splunk | Sigma, KQL, SPL | Detection Engineering, Incident Response |
| [Detection Rule — Unmanaged Mobile Access to Corporate Apps](sigma/unmanaged-mobile-access.md) | Entry | Entra ID, Intune, Microsoft 365 | Sigma, KQL | Detection Engineering, Compliance |
| [Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](sigma/wlan-events.md) | Entry | Windows, Windows Server | Sigma, KQL, SPL | Detection Engineering, Investigation |
| [Fundamentals — Cross-Site Request Forgery (CSRF) & State Defense](../fundamentals/web-apps/csrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Cross-Site Scripting (XSS) & Content Security Policy](../fundamentals/web-apps/xss-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Server-Side Request Forgery (SSRF) & Egress Defense](../fundamentals/web-apps/ssrf-defense.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — SQL Injection & Parameterized Defense](../fundamentals/web-apps/sql-injection.md) | Entry | Linux, Windows | HTTP, Python, PowerShell | Hardening, Investigation, Detection Engineering |
| [Fundamentals — Sysmon Telemetry & Endpoint Monitoring](../fundamentals/systems/sysmon.md) | Entry | Windows, Linux | PowerShell, Bash | Threat Hunting, Detection Engineering |
| [Google Cloud Logging & BigQuery Log Queries](../platforms/gcp/monitoring-logs.md) | Entry | GCP | Bash | Investigation, Troubleshooting, Detection Engineering, Administration |
| [Google Cloud Persistence & Threat Hunting](../platforms/gcp/persistence-hunting.md) | Entry | GCP | Bash, Python | Threat Hunting, Incident Response, Investigation, Detection Engineering |
| [KQL Credential Access and Memory Dumping Queries](kql/credential-access.md) | Entry | Microsoft Defender, Windows, Windows Server | KQL | Threat Hunting, Detection Engineering, Incident Response |
| [KQL File, Registry and Persistence Hunting](kql/file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](kql/fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](kql/logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](kql/network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](kql/process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Linux Audit Daemon (auditd) & Kernel Telemetry](../platforms/linux/auditd.md) | Entry | Linux | Bash | Forensics, Detection Engineering |
| [S1QL Defense Impairment and Tampering Queries](s1ql/defense-evasion.md) | Entry | SentinelOne, Windows, Linux | S1QL | Threat Hunting, Incident Response, Detection Engineering |
| [S1QL Fundamentals](s1ql/fundamentals.md) | Entry | SentinelOne | S1QL | Threat Hunting, Investigation, Detection Engineering |
| [Sigma Rule Examples](sigma/examples.md) | Entry | Windows | Sigma | Detection Engineering, Threat Hunting |
| [Sigma Rules for Cloud Identity and Entra ID Attacks](sigma/cloud-identity-rules.md) | Entry | Entra ID, Microsoft 365, Azure | Sigma | Detection Engineering, Threat Hunting |
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
| [Threat Actor Intelligence Profiles & TTP Reference Cards](../references/threat-actor-profiles.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft 365 | KQL, SPL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Windows Event ID Reference](../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |
| [Windows Process Parent/Child Chains — Know Normal](../references/windows-process-chains.md) | Reference | Windows, Windows Server | PowerShell, KQL, SPL | Investigation, Threat Hunting, Incident Response, Detection Engineering |
| [Intrusion Detection and Prevention (IDS/IPS)](../fundamentals/concepts/ids-ips.md) | Concept | Linux, Windows, Microsoft Defender | Bash, KQL | Detection Engineering, Threat Hunting, Hardening |
| [Penetration Testing and Red Teaming (Methodology and Detection)](../fundamentals/concepts/penetration-testing.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Assurance, Threat Hunting, Detection Engineering |
| [Security Information and Event Management (SIEM)](../fundamentals/concepts/siem.md) | Concept | Splunk, Microsoft Defender, Azure | SPL, KQL | Detection Engineering, Investigation, Threat Hunting |
| [Surveillance, Counter-Surveillance and Deception](../fundamentals/concepts/surveillance-deception.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, KQL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Intelligence and the Cyber Kill Chain](../fundamentals/concepts/threat-intelligence-kill-chain.md) | Concept | Windows, Microsoft Defender | KQL, PowerShell | Threat Intelligence, Threat Hunting, Detection Engineering |

<!-- /cc:index -->
