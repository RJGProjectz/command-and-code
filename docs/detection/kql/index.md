---
title: KQL
type: index
---

# KQL — Kusto Query Language

Used by **Microsoft Defender XDR advanced hunting** and **Microsoft Sentinel**.

| Page | Covers |
| --- | --- |
| [Fundamentals](fundamentals.md) | operators, time filtering, summarize, joins, parsing, dynamic data |
| [Process events](process-events.md) | `DeviceProcessEvents` — PowerShell, LOLBins, Office children, process trees |
| [Network events](network-events.md) | `DeviceNetworkEvents` — listeners, outbound, beaconing, RDP, DNS |
| [File and registry events](file-registry-events.md) | `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceEvents` — persistence |
| [Logons and identity](logon-identity.md) | `DeviceLogonEvents`, `IdentityLogonEvents`, `SigninLogs`, `AuditLogs` |

## Everything tagged KQL

<!-- cc:index languages="KQL" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Account Compromise Investigation](../../tasks/incident-response/account-compromise.md) | Workflow | Entra ID, Exchange Online, Microsoft 365, Windows | PowerShell, KQL | Incident Response, Investigation |
| [Alert Tuning and False Positive Management](../../tasks/detection-engineering/alert-tuning-false-positive-management.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL | Detection Engineering, Investigation, Incident Response |
| [Cyber Threat Intelligence — Adversary Emulation & ATT&CK Profiling](../../tasks/threat-intelligence/adversary-emulation-profiling.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Assurance |
| [Cyber Threat Intelligence — IoC Ingestion, Aging & Confidence Scoring](../../tasks/threat-intelligence/ioc-lifecycle-scoring.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Investigation |
| [Cyber Threat Intelligence — STIX 2.1 & TAXII Feed Ingestion Pipeline](../../tasks/threat-intelligence/stix-taxii-pipeline.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | Python, PowerShell, Bash, KQL, SPL | Threat Intelligence, Detection Engineering, Threat Hunting |
| [Detection Development Lifecycle (DDLC) and Testing](../../tasks/detection-engineering/detection-development-lifecycle.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, Sigma, PowerShell | Detection Engineering, Threat Hunting, Incident Response |
| [Failed Authentication Investigation](../../tasks/investigation/failed-authentication.md) | Workflow | Windows, Windows Server, Linux, Entra ID, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Troubleshooting |
| [Hunting Cloud Identity Persistence in Entra ID and Microsoft 365](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Hunting Kerberoasting and AS-REP Roasting in Active Directory](../../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) | Workflow | Active Directory, Windows, Windows Server, Splunk, Microsoft Defender | PowerShell, KQL, SPL | Threat Hunting, Investigation, Incident Response |
| [Hunting Living-off-the-Land Binaries and Scripts (LOLBins)](../../tasks/threat-hunting/lolbins-execution-hunting.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Investigation Playbook — Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md) | Workflow | Azure, Microsoft 365 | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) | Workflow | Entra ID, Azure | KQL, PowerShell | Incident Response, Investigation |
| [Investigation Playbook — Phishing Email Triage](../../tasks/incident-response/phishing-email-triage.md) | Workflow | Microsoft 365, Exchange Online | PowerShell, KQL | Incident Response, Investigation |
| [Malware Triage](../../tasks/incident-response/malware-triage.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics |
| [Network Investigation](../../tasks/investigation/network-investigation.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Possible Lateral Movement](../../tasks/threat-hunting/lateral-movement.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, KQL, SPL | Threat Hunting, Incident Response, Investigation |
| [Registry Persistence Investigation](../../tasks/investigation/registry-persistence.md) | Workflow | Windows, Microsoft Defender, SentinelOne | PowerShell, Windows CLI, KQL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Scheduled Task Investigation](../../tasks/investigation/scheduled-task-investigation.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, Windows CLI, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting |
| [Suspicious Outbound Connection](../../tasks/investigation/suspicious-outbound-connection.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk | PowerShell, Bash, KQL, SPL | Investigation, Incident Response, Threat Hunting |
| [Suspicious PowerShell Investigation](../../tasks/incident-response/suspicious-powershell.md) | Workflow | Windows, Microsoft Defender, Splunk, SentinelOne | PowerShell, KQL, SPL, S1QL | Incident Response, Investigation |
| [Suspicious Process Investigation](../../tasks/incident-response/suspicious-process.md) | Workflow | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Investigation |
| [Suspicious Service Investigation](../../tasks/investigation/suspicious-service.md) | Workflow | Windows, Windows Server, Microsoft Defender, Splunk | PowerShell, Windows CLI, KQL, SPL | Investigation, Incident Response |
| [Threat Hunting — Cloud Identity, OAuth Grants & Ephemeral Asset Anomalies](../../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) | Workflow | Entra ID, Microsoft 365, Azure, Microsoft Defender, Splunk | KQL, SPL, PowerShell | Threat Hunting, Incident Response, Investigation |
| [Threat Hunting — Cross-Platform Behavioral Telemetry (Windows & Linux)](../../tasks/threat-hunting/cross-platform-behavioral-hunting.md) | Workflow | Windows, Windows Server, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Hunting — Hypothesis-Driven Methodology & Hunt Lifecycle Framework](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Threat Hunting, Detection Engineering, Incident Response |
| [Threat Hunting — Statistical Baselining & Frequency Analysis (LFO)](../../tasks/threat-hunting/statistical-baselining-frequency-analysis.md) | Workflow | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | KQL, SPL, S1QL, PowerShell, Bash | Threat Hunting, Detection Engineering, Investigation |
| [Conditional Access](../../platforms/microsoft-365/conditional-access.md) | Entry | Microsoft 365, Entra ID | PowerShell, KQL | Administration, Hardening, Investigation, Troubleshooting |
| [Detection Rule — ARP Spoofing (DAI and arpwatch)](../sigma/arp-spoofing-dai.md) | Entry | Linux, Splunk | Sigma, SPL, KQL | Detection Engineering, Threat Hunting |
| [Detection Rule — CI/CD Secret Leak](../sigma/cicd-secret-leak.md) | Entry | Splunk | Sigma, SPL, KQL | Detection Engineering, Incident Response |
| [Detection Rule — Cryptomining (Resource Hijacking)](../sigma/cryptomining.md) | Entry | Windows, Linux, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Honeytoken and Honey Account Use](../sigma/honeytoken-access.md) | Entry | Active Directory, Windows Server, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — LLMNR / NBT-NS Poisoning](../sigma/llmnr-nbtns-poisoning.md) | Entry | Windows, Microsoft Defender | Sigma, KQL, SPL | Detection Engineering, Threat Hunting |
| [Detection Rule — Network Flood (DoS / DDoS)](../sigma/dos-flood.md) | Entry | Azure, Splunk | Sigma, KQL, SPL | Detection Engineering, Incident Response |
| [Detection Rule — Unmanaged Mobile Access to Corporate Apps](../sigma/unmanaged-mobile-access.md) | Entry | Entra ID, Intune, Microsoft 365 | Sigma, KQL | Detection Engineering, Compliance |
| [Detection Rules — Wi-Fi (WLAN-AutoConfig and Unknown Devices)](../sigma/wlan-events.md) | Entry | Windows, Windows Server | Sigma, KQL, SPL | Detection Engineering, Investigation |
| [KQL Credential Access and Memory Dumping Queries](credential-access.md) | Entry | Microsoft Defender, Windows, Windows Server | KQL | Threat Hunting, Detection Engineering, Incident Response |
| [KQL File, Registry and Persistence Hunting](file-registry-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Fundamentals](fundamentals.md) | Entry | Microsoft Defender, Microsoft 365 | KQL | Threat Hunting, Detection Engineering, Investigation |
| [KQL Logon and Identity Hunting](logon-identity.md) | Entry | Microsoft Defender, Entra ID, Microsoft 365, Windows | KQL | Threat Hunting, Investigation, Incident Response, Detection Engineering |
| [KQL Network Event Hunting](network-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Investigation, Detection Engineering, Incident Response |
| [KQL Process Event Hunting](process-events.md) | Entry | Microsoft Defender, Windows | KQL | Threat Hunting, Detection Engineering, Investigation, Incident Response |
| [Microsoft Defender XDR and Defender for Endpoint](../../platforms/microsoft-365/defender.md) | Entry | Microsoft 365, Microsoft Defender, Windows | PowerShell, KQL | Incident Response, Threat Hunting, Administration, Automation |
| [Cross-Platform Equivalents](../../references/equivalents.md) | Reference | Windows, Linux, Microsoft Defender, Splunk, SentinelOne | PowerShell, Bash, KQL, SPL, S1QL | Investigation, Incident Response, Threat Hunting, Administration |
| [Knowledge Graph Efficacy & Operational Coverage Matrix](../../references/coverage-matrix.md) | Reference | Windows, Windows Server, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | PowerShell, Bash, Python, KQL, SPL, S1QL, REST API | Administration, Incident Response, Threat Hunting, Detection Engineering, Hardening, Assurance, Governance |
| [MITRE ATT&CK® Enterprise Matrix & Navigator Coverage](../../references/mitre-attack-matrix.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft Defender, SentinelOne, Splunk | KQL, SPL, S1QL, PowerShell, Bash | Detection Engineering, Incident Response, Threat Hunting, Hardening |
| [Threat Actor Intelligence Profiles & TTP Reference Cards](../../references/threat-actor-profiles.md) | Reference | Windows, Linux, Azure, Entra ID, Microsoft 365 | KQL, SPL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Windows Event ID Reference](../../references/windows-event-ids.md) | Reference | Windows, Windows Server | PowerShell, SPL, KQL | Investigation, Incident Response, Detection Engineering, Forensics |
| [Anonymity Networks and the Dark Web (Tor, I2P, Tails)](../../fundamentals/concepts/anonymity-dark-web.md) | Concept | Windows, Linux, Microsoft Defender | KQL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Investigation |
| [Authentication, MFA, SSO and Federation](../../fundamentals/concepts/authentication-mfa-sso.md) | Concept | Windows, Entra ID, Microsoft 365 | PowerShell, KQL | Investigation, Hardening, Incident Response |
| [Cloud-Native Security (Containers, Kubernetes, Microservices)](../../fundamentals/concepts/cloud-native-security.md) | Concept | Linux, Azure | Bash, KQL | Hardening, Threat Hunting, Assurance |
| [Credential Dumping](../../fundamentals/concepts/credential-dumping.md) | Concept | Windows, Microsoft Defender, Active Directory | PowerShell, KQL | Incident Response, Threat Hunting, Hardening |
| [Cryptographic Attacks and Cryptanalysis](../../fundamentals/concepts/cryptographic-attacks.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Threat Hunting, Hardening, Assurance |
| [Identity and Access Management (IAM, PAM, Directory Services)](../../fundamentals/concepts/identity-access-management.md) | Concept | Windows Server, Entra ID, Azure | PowerShell, KQL | Administration, Hardening, Assurance |
| [Intrusion Detection and Prevention (IDS/IPS)](../../fundamentals/concepts/ids-ips.md) | Concept | Linux, Windows, Microsoft Defender | Bash, KQL | Detection Engineering, Threat Hunting, Hardening |
| [Kerberoasting](../../fundamentals/concepts/kerberoasting.md) | Concept | Active Directory, Windows Server, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Investigation |
| [Malware Types and Analysis (Spyware, RATs, Rootkits)](../../fundamentals/concepts/malware-types-analysis.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics, Threat Intelligence |
| [Mobile Device and Application Security](../../fundamentals/concepts/mobile-security.md) | Concept | Intune, Microsoft 365 | PowerShell, KQL | Hardening, Assurance, Investigation |
| [Password Attacks and Defences (Spraying, Cracking, Wordlists)](../../fundamentals/concepts/password-attacks.md) | Concept | Windows, Entra ID, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Incident Response |
| [Penetration Testing and Red Teaming (Methodology and Detection)](../../fundamentals/concepts/penetration-testing.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Assurance, Threat Hunting, Detection Engineering |
| [Port Scanning](../../fundamentals/concepts/port-scanning.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Investigation, Threat Hunting, Hardening |
| [Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)](../../fundamentals/concepts/privacy-laws.md) | Concept | Microsoft 365, Windows | PowerShell, KQL | Compliance, Incident Response, Assurance |
| [Security Information and Event Management (SIEM)](../../fundamentals/concepts/siem.md) | Concept | Splunk, Microsoft Defender, Azure | SPL, KQL | Detection Engineering, Investigation, Threat Hunting |
| [Social Engineering (Phishing, Vishing, Pretexting, Tailgating)](../../fundamentals/concepts/social-engineering.md) | Concept | Microsoft 365, Exchange Online, Microsoft Defender | KQL, PowerShell | Incident Response, Investigation, Hardening |
| [Surveillance, Counter-Surveillance and Deception](../../fundamentals/concepts/surveillance-deception.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, KQL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Intelligence and the Cyber Kill Chain](../../fundamentals/concepts/threat-intelligence-kill-chain.md) | Concept | Windows, Microsoft Defender | KQL, PowerShell | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Vulnerability Assessment and Patch Management](../../fundamentals/concepts/vulnerability-management.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Hardening, Assurance, Administration |

<!-- /cc:index -->
