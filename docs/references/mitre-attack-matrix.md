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
last_verified: 2026-10-13
difficulty: advanced
tags:
  - mitre-attack
  - tactics
  - techniques
  - navigator
  - coverage
---

# MITRE ATT&CK® Enterprise Matrix & Navigator Coverage

A verifiable cross-walk indexing all adversary techniques, tactics, detection signatures, and response playbooks in **Command & Code** mapped against the **MITRE ATT&CK® Enterprise Taxonomy (v20)**.

---

## 1. Executive Matrix Summary

```text
TOTAL VALIDATED TECHNIQUES COVERED : 201 Enterprise Techniques
OFFICIAL NAVIGATOR LAYER ARTIFACT  : site/mitre_attack_coverage.json
TACTIC COVERAGE SPAN               : 15 of 15 Enterprise tactics
```

> [!TIP]
> **Importing to ATT&CK Navigator:**
> Open [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), select **Open Existing Layer** -> **Upload from local**, and upload `site/mitre_attack_coverage.json` to visualize your team's live operational coverage heatmap.

---

## 2. Technique Coverage by ATT&CK Tactic

| Technique ID | Technique Name | Primary Tactics | Operational Guides & Procedures |
|:---|:---|:---|:---|
| **`T1003`** | OS Credential Dumping | Credential Access | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) · [Detection Development Lifecycle](../tasks/detection-engineering/detection-development-lifecycle.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) *(+2 more)* |
| **`T1003.001`** | LSASS Memory | Credential Access | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) |
| **`T1003.002`** | Security Account Manager | Credential Access | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) |
| **`T1003.003`** | NTDS | Credential Access | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) |
| **`T1003.004`** | LSA Secrets | Credential Access | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) |
| **`T1007`** | System Service Discovery | Discovery | [Services Daemons](../fundamentals/concepts/services-daemons.md) |
| **`T1012`** | Query Registry | Discovery | [Windows Registry](../fundamentals/concepts/windows-registry.md) |
| **`T1014`** | Rootkit | Stealth | [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) · [Malware Types Analysis](../fundamentals/concepts/malware-types-analysis.md) |
| **`T1016`** | System Network Configuration Discovery | Discovery | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1021`** | Remote Services | Lateral Movement | [Windows Process Chains](../references/windows-process-chains.md) · [Smb Lateral Movement](../tasks/incident-response/smb-lateral-movement.md) · [Penetration Testing](../fundamentals/concepts/penetration-testing.md) · [Index](../detection/mitre-attack/index.md) *(+1 more)* |
| **`T1021.001`** | Remote Desktop Protocol | Lateral Movement | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Index](../detection/mitre-attack/index.md) · [Windows Events](../detection/spl/windows-events.md) |
| **`T1021.002`** | SMB/Windows Admin Shares | Lateral Movement | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Smb Lateral Movement](../tasks/incident-response/smb-lateral-movement.md) · [Index](../detection/mitre-attack/index.md) · [Lateral Movement Smb](../detection/spl/lateral-movement-smb.md) *(+1 more)* |
| **`T1021.003`** | Community Technique | Execution | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1021.006`** | Windows Remote Management | Lateral Movement | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1027`** | Obfuscated Files or Information | Stealth | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Process Events](../detection/kql/process-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1036`** | Masquerading | Stealth | [Hash Functions](../fundamentals/concepts/hash-functions.md) · [Processes Threads](../fundamentals/concepts/processes-threads.md) |
| **`T1036.003`** | Rename Legitimate Utilities | Stealth | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Hunting](../detection/s1ql/hunting.md) |
| **`T1037`** | Boot or Logon Initialization Scripts | Persistence, Privilege Escalation | [Persistence Hunting](../platforms/gcp/persistence-hunting.md) · [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) |
| **`T1040`** | Network Sniffing | Credential Access, Discovery | [Packet Sniffing](../fundamentals/concepts/packet-sniffing.md) · [Post Quantum Cryptography](../fundamentals/concepts/post-quantum-cryptography.md) · [Wifi Passphrase Attacks](../fundamentals/concepts/wifi-passphrase-attacks.md) · [Wifi Security](../fundamentals/concepts/wifi-security.md) |
| **`T1046`** | Network Service Discovery | Discovery | [Port Scanning](../fundamentals/concepts/port-scanning.md) |
| **`T1047`** | Windows Management Instrumentation | Execution | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Windows Process Chains](../references/windows-process-chains.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) |
| **`T1048`** | Exfiltration Over Alternative Protocol | Exfiltration | [Dns Tunneling](../detection/spl/dns-tunneling.md) |
| **`T1053`** | Scheduled Task/Job | Execution, Persistence, Privilege Escalation | [Windows Process Chains](../references/windows-process-chains.md) · [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Scheduled Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) *(+6 more)* |
| **`T1053.003`** | Cron | Execution, Persistence, Privilege Escalation | [Cron](../platforms/linux/cron.md) · [Index](../detection/mitre-attack/index.md) · [Hunting](../detection/s1ql/hunting.md) |
| **`T1053.005`** | Scheduled Task | Execution, Persistence, Privilege Escalation | [Windows Process Chains](../references/windows-process-chains.md) · [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Hypothesis Driven Hunting Framework](../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) · [Scheduled Tasks](../platforms/windows/scheduled-tasks.md) *(+4 more)* |
| **`T1053.006`** | Systemd Timers | Execution, Persistence, Privilege Escalation | [Systemd](../platforms/linux/systemd.md) |
| **`T1055`** | Process Injection | Privilege Escalation, Stealth | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Malware Types Analysis](../fundamentals/concepts/malware-types-analysis.md) · [Processes Threads](../fundamentals/concepts/processes-threads.md) |
| **`T1057`** | Process Discovery | Discovery | [Processes Threads](../fundamentals/concepts/processes-threads.md) |
| **`T1059`** | Command and Scripting Interpreter | Execution | [Terminal Sessions](../platforms/linux/terminal-sessions.md) · [Networking Sockets](../languages/bash/networking-sockets.md) · [Penetration Testing](../fundamentals/concepts/penetration-testing.md) · [Process Events](../detection/kql/process-events.md) *(+1 more)* |
| **`T1059.001`** | PowerShell | Execution | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Detection Development Lifecycle](../tasks/detection-engineering/detection-development-lifecycle.md) · [Suspicious Powershell](../tasks/incident-response/suspicious-powershell.md) · [Hypothesis Driven Hunting Framework](../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) *(+6 more)* |
| **`T1059.003`** | Windows Command Shell | Execution | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1059.004`** | Unix Shell | Execution | [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Terminal Sessions](../platforms/linux/terminal-sessions.md) · [Networking Sockets](../languages/bash/networking-sockets.md) |
| **`T1059.005`** | Visual Basic | Execution | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) |
| **`T1059.007`** | JavaScript | Execution | [Index](../detection/mitre-attack/index.md) |
| **`T1068`** | Exploitation for Privilege Escalation | Privilege Escalation | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Software](../platforms/windows/software.md) · [Cia Triad](../fundamentals/concepts/cia-triad.md) *(+1 more)* |
| **`T1069`** | Permission Groups Discovery | Discovery | [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1070`** | Indicator Removal | Stealth | [Shell Command History](../tasks/administration/shell-command-history.md) · [Files Directories](../platforms/windows/files-directories.md) · [Digital Forensics](../fundamentals/concepts/digital-forensics.md) · [File Systems](../fundamentals/concepts/file-systems.md) |
| **`T1070.003`** | Clear Command History | Stealth | [Shell Command History](../tasks/administration/shell-command-history.md) |
| **`T1070.006`** | Timestomp | Stealth | [Files Directories](../platforms/windows/files-directories.md) · [File Systems](../fundamentals/concepts/file-systems.md) |
| **`T1071`** | Application Layer Protocol | Command and Control | [Dns](../fundamentals/dns.md) · [Network Events](../detection/kql/network-events.md) · [Index](../detection/mitre-attack/index.md) · [Dns Tunneling](../detection/spl/dns-tunneling.md) |
| **`T1071.001`** | Web Protocols | Command and Control | [Network Dns](../detection/spl/network-dns.md) |
| **`T1071.004`** | DNS | Command and Control | [Dns](../fundamentals/dns.md) · [Hunting](../detection/s1ql/hunting.md) · [Dns Tunneling](../detection/spl/dns-tunneling.md) · [Network Dns](../detection/spl/network-dns.md) |
| **`T1078`** | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | [Linux Service Accounts Least Privilege](../tasks/administration/linux-service-accounts-least-privilege.md) · [Windows Service Accounts Least Privilege](../tasks/administration/windows-service-accounts-least-privilege.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Compromised Service Principal](../tasks/incident-response/compromised-service-principal.md) *(+8 more)* |
| **`T1078.002`** | Domain Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | [Service Account Audit](../tasks/assurance/service-account-audit.md) |
| **`T1078.003`** | Local Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | [Linux Service Accounts Least Privilege](../tasks/administration/linux-service-accounts-least-privilege.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1078.004`** | Cloud Accounts | Initial Access, Persistence, Privilege Escalation, Stealth | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Compromised Service Principal](../tasks/incident-response/compromised-service-principal.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) *(+3 more)* |
| **`T1083`** | File and Directory Discovery | Discovery | [File Systems](../fundamentals/concepts/file-systems.md) |
| **`T1087`** | Account Discovery | Discovery | [Honeytoken Access](../detection/sigma/honeytoken-access.md) |
| **`T1087.002`** | Domain Account | Discovery | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Honeytoken Access](../detection/sigma/honeytoken-access.md) |
| **`T1090`** | Proxy | Command and Control | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Anonymity Dark Web](../fundamentals/concepts/anonymity-dark-web.md) · [Proxy Servers](../fundamentals/concepts/proxy-servers.md) |
| **`T1090.001`** | Internal Proxy | Command and Control | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1090.003`** | Multi-hop Proxy | Command and Control | [Anonymity Dark Web](../fundamentals/concepts/anonymity-dark-web.md) |
| **`T1091`** | Replication Through Removable Media | Initial Access, Lateral Movement | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) |
| **`T1095`** | Non-Application Layer Protocol | Command and Control | [Hypothesis Driven Hunting Framework](../tasks/threat-hunting/hypothesis-driven-hunting-framework.md) |
| **`T1098`** | Account Manipulation | Persistence, Privilege Escalation | [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) *(+10 more)* |
| **`T1098.001`** | Additional Cloud Credentials | Persistence, Privilege Escalation | [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) *(+4 more)* |
| **`T1098.003`** | Additional Cloud Roles | Persistence, Privilege Escalation | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) *(+3 more)* |
| **`T1098.004`** | SSH Authorized Keys | Persistence, Privilege Escalation | [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) · [Persistence Hunting](../platforms/gcp/persistence-hunting.md) · [Ssh](../platforms/linux/ssh.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1098.005`** | Device Registration | Persistence, Privilege Escalation | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Entra](../platforms/microsoft-365/entra.md) |
| **`T1105`** | Ingress Tool Transfer | Command and Control | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Process Events](../detection/kql/process-events.md) · [Hunting](../detection/s1ql/hunting.md) · [Powershell](../detection/spl/powershell.md) |
| **`T1106`** | Native API | Execution | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1110`** | Brute Force | Credential Access | [Authentication Mfa Sso](../fundamentals/concepts/authentication-mfa-sso.md) · [Cryptographic Attacks](../fundamentals/concepts/cryptographic-attacks.md) · [Hash Functions](../fundamentals/concepts/hash-functions.md) · [Password Attacks](../fundamentals/concepts/password-attacks.md) *(+5 more)* |
| **`T1110.001`** | Password Guessing | Credential Access | [Password Attacks](../fundamentals/concepts/password-attacks.md) · [Hunting](../detection/s1ql/hunting.md) · [Brute Force](../detection/spl/brute-force.md) · [Windows Events](../detection/spl/windows-events.md) |
| **`T1110.002`** | Password Cracking | Credential Access | [Cryptographic Attacks](../fundamentals/concepts/cryptographic-attacks.md) · [Hash Functions](../fundamentals/concepts/hash-functions.md) · [Password Attacks](../fundamentals/concepts/password-attacks.md) · [Wifi Passphrase Attacks](../fundamentals/concepts/wifi-passphrase-attacks.md) |
| **`T1110.003`** | Password Spraying | Credential Access | [Password Attacks](../fundamentals/concepts/password-attacks.md) · [Logon Identity](../detection/kql/logon-identity.md) · [Index](../detection/mitre-attack/index.md) · [Windows Events](../detection/spl/windows-events.md) |
| **`T1110.004`** | Credential Stuffing | Credential Access | [Password Attacks](../fundamentals/concepts/password-attacks.md) |
| **`T1112`** | Modify Registry | Persistence, Defense Impairment | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) |
| **`T1134`** | Access Token Manipulation | Privilege Escalation, Stealth | [Processes Threads](../fundamentals/concepts/processes-threads.md) · [Windows Processes](../fundamentals/systems/windows-processes.md) |
| **`T1134.004`** | Parent PID Spoofing | Privilege Escalation, Stealth | [Processes Threads](../fundamentals/concepts/processes-threads.md) · [Windows Processes](../fundamentals/systems/windows-processes.md) |
| **`T1136`** | Create Account | Persistence | [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) · [Identity Access Management](../fundamentals/concepts/identity-access-management.md) · [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1136.001`** | Community Technique | Execution | [Windows Events](../detection/spl/windows-events.md) |
| **`T1136.003`** | Cloud Account | Persistence | [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) · [Persistence Hunting](../platforms/gcp/persistence-hunting.md) · [Persistence Hunting](../platforms/github/persistence-hunting.md) |
| **`T1137`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1137.002`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1187`** | Forced Authentication | Credential Access | [Ad Kerberos Ldap Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md) |
| **`T1190`** | Exploit Public-Facing Application | Initial Access | [Secure Sdlc Devsecops](../fundamentals/concepts/secure-sdlc-devsecops.md) · [Vulnerability Management](../fundamentals/concepts/vulnerability-management.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1195`** | Supply Chain Compromise | Initial Access | [Secure Sdlc Devsecops](../fundamentals/concepts/secure-sdlc-devsecops.md) |
| **`T1195.001`** | Compromise Software Dependencies and Development Tools | Initial Access | [Persistence Hunting](../platforms/github/persistence-hunting.md) · [Secure Sdlc Devsecops](../fundamentals/concepts/secure-sdlc-devsecops.md) |
| **`T1200`** | Hardware Additions | Initial Access | [Mac Address Spoofing](../fundamentals/concepts/mac-address-spoofing.md) |
| **`T1204`** | User Execution | Execution | [Cis Block Monitor](../tasks/hardening/cis-block-monitor.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Malware Types Analysis](../fundamentals/concepts/malware-types-analysis.md) *(+1 more)* |
| **`T1204.002`** | Malicious File | Execution | [Cis Block Monitor](../tasks/hardening/cis-block-monitor.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Process Events](../detection/kql/process-events.md) |
| **`T1210`** | Exploitation of Remote Services | Lateral Movement | [Vulnerability Management](../fundamentals/concepts/vulnerability-management.md) |
| **`T1213.003`** | Community Technique | Execution | [Persistence Hunting](../platforms/github/persistence-hunting.md) |
| **`T1218`** | System Binary Proxy Execution | Stealth | [Windows Process Chains](../references/windows-process-chains.md) · [Process Events](../detection/kql/process-events.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1218.005`** | Mshta | Stealth | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1218.010`** | Regsvr32 | Stealth | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1218.011`** | Rundll32 | Stealth | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1219`** | Remote Access Tools | Command and Control | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Software](../platforms/windows/software.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1222`** | File and Directory Permissions Modification | Defense Impairment | [Access Control Models](../fundamentals/concepts/access-control-models.md) · [File Systems](../fundamentals/concepts/file-systems.md) |
| **`T1484`** | Domain or Tenant Policy Modification | Privilege Escalation, Defense Impairment | [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) · [Cloud Identity Rules](../detection/sigma/cloud-identity-rules.md) |
| **`T1484.002`** | Trust Modification | Privilege Escalation, Defense Impairment | [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) · [Persistence Hunting](../platforms/gcp/persistence-hunting.md) *(+1 more)* |
| **`T1485`** | Data Destruction | Impact | [Keys Secrets](../platforms/aws/keys-secrets.md) · [Digital Forensics](../fundamentals/concepts/digital-forensics.md) |
| **`T1486`** | Data Encrypted for Impact | Impact | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Ransomware Host Isolation](../tasks/incident-response/ransomware-host-isolation.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Cryptography Fundamentals](../fundamentals/concepts/cryptography-fundamentals.md) *(+2 more)* |
| **`T1489`** | Service Stop | Impact | [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Services Daemons](../fundamentals/concepts/services-daemons.md) |
| **`T1490`** | Inhibit System Recovery | Impact | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Digital Forensics](../fundamentals/concepts/digital-forensics.md) · [Ransomware](../fundamentals/concepts/ransomware.md) *(+1 more)* |
| **`T1496`** | Resource Hijacking | Impact | [Azure Resource Hijacking](../tasks/incident-response/azure-resource-hijacking.md) · [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) · [Cloud Native Security](../fundamentals/concepts/cloud-native-security.md) · [Zero Knowledge Homomorphic Blockchain](../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md) *(+1 more)* |
| **`T1498`** | Network Denial of Service | Impact | [Denial Of Service](../fundamentals/concepts/denial-of-service.md) · [Wifi Deauth Rogue Ap](../fundamentals/concepts/wifi-deauth-rogue-ap.md) · [Dos Flood](../detection/sigma/dos-flood.md) |
| **`T1499`** | Endpoint Denial of Service | Impact | [Denial Of Service](../fundamentals/concepts/denial-of-service.md) · [Dos Flood](../detection/sigma/dos-flood.md) |
| **`T1505`** | Server Software Component | Persistence | [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1505.003`** | Web Shell | Persistence | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Windows Process Chains](../references/windows-process-chains.md) |
| **`T1525`** | Implant Internal Image | Persistence | [Persistence Hunting](../platforms/gcp/persistence-hunting.md) |
| **`T1528`** | Steal Application Access Token | Credential Access | [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) · [Cloud Identity Persistence Hunting](../tasks/threat-hunting/cloud-identity-persistence-hunting.md) · [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) · [Persistence Hunting](../platforms/github/persistence-hunting.md) *(+2 more)* |
| **`T1529`** | System Shutdown/Reboot | Impact | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1530`** | Data from Cloud Storage | Collection | [Privacy Laws](../fundamentals/concepts/privacy-laws.md) |
| **`T1539`** | Steal Web Session Cookie | Credential Access | [Authentication Mfa Sso](../fundamentals/concepts/authentication-mfa-sso.md) |
| **`T1542`** | Pre-OS Boot | Persistence, Stealth | [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) |
| **`T1542.003`** | Bootkit | Persistence, Stealth | [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) |
| **`T1543`** | Create or Modify System Process | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Scheduled Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) · [Systemd](../platforms/linux/systemd.md) · [Services](../platforms/windows/services.md) *(+4 more)* |
| **`T1543.001`** | Launch Agent | Persistence, Privilege Escalation | [Scheduled Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) |
| **`T1543.002`** | Systemd Service | Persistence, Privilege Escalation | [Systemd](../platforms/linux/systemd.md) · [Services Daemons](../fundamentals/concepts/services-daemons.md) · [Index](../detection/mitre-attack/index.md) · [Hunting](../detection/s1ql/hunting.md) |
| **`T1543.003`** | Windows Service | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Services](../platforms/windows/services.md) · [Services Daemons](../fundamentals/concepts/services-daemons.md) · [File Registry Events](../detection/kql/file-registry-events.md) *(+2 more)* |
| **`T1543.004`** | Launch Daemon | Persistence, Privilege Escalation | [Scheduled Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) |
| **`T1546`** | Event Triggered Execution | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Registry](../platforms/windows/registry.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1546.002`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1546.003`** | Windows Management Instrumentation Event Subscription | Persistence, Privilege Escalation | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) |
| **`T1546.007`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1546.008`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1546.009`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1546.010`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1546.012`** | Image File Execution Options Injection | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Registry](../platforms/windows/registry.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1546.015`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1547`** | Boot or Logon Autostart Execution | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Registry](../platforms/windows/registry.md) · [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) *(+2 more)* |
| **`T1547.001`** | Registry Run Keys / Startup Folder | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Registry](../platforms/windows/registry.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) · [File Registry Events](../detection/kql/file-registry-events.md) *(+2 more)* |
| **`T1547.002`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1547.003`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1547.004`** | Winlogon Helper DLL | Persistence, Privilege Escalation | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) · [Windows Registry](../fundamentals/concepts/windows-registry.md) |
| **`T1547.005`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1547.010`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1547.014`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1548`** | Abuse Elevation Control Mechanism | Privilege Escalation | [Linux Service Accounts Least Privilege](../tasks/administration/linux-service-accounts-least-privilege.md) · [Linux Sudoers Integrity](../tasks/assurance/linux-sudoers-integrity.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Users Permissions](../platforms/linux/users-permissions.md) *(+3 more)* |
| **`T1548.001`** | Setuid and Setgid | Privilege Escalation | [Users Permissions](../platforms/linux/users-permissions.md) · [File Systems](../fundamentals/concepts/file-systems.md) · [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1548.002`** | Bypass User Account Control | Privilege Escalation | [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1548.003`** | Sudo and Sudo Caching | Privilege Escalation | [Linux Service Accounts Least Privilege](../tasks/administration/linux-service-accounts-least-privilege.md) · [Linux Sudoers Integrity](../tasks/assurance/linux-sudoers-integrity.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Users Groups Permissions](../fundamentals/concepts/users-groups-permissions.md) |
| **`T1550`** | Use Alternate Authentication Material | Lateral Movement | [Credential Dumping](../fundamentals/concepts/credential-dumping.md) · [Hash Functions](../fundamentals/concepts/hash-functions.md) |
| **`T1550.002`** | Pass the Hash | Lateral Movement | [Credential Dumping](../fundamentals/concepts/credential-dumping.md) · [Hash Functions](../fundamentals/concepts/hash-functions.md) |
| **`T1552`** | Unsecured Credentials | Credential Access | [Linux Service Secrets Storage](../tasks/administration/linux-service-secrets-storage.md) · [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) *(+3 more)* |
| **`T1552.001`** | Credentials In Files | Credential Access | [Linux Service Secrets Storage](../tasks/administration/linux-service-secrets-storage.md) · [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Persistence Hunting](../platforms/github/persistence-hunting.md) *(+2 more)* |
| **`T1552.004`** | Community Technique | Execution | [Linux Service Secrets Storage](../tasks/administration/linux-service-secrets-storage.md) · [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) |
| **`T1553`** | Subvert Trust Controls | Defense Impairment | [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1553.002`** | Code Signing | Defense Impairment | [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1555`** | Credentials from Password Stores | Credential Access | [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Malware Types Analysis](../fundamentals/concepts/malware-types-analysis.md) · [Credential Access](../detection/kql/credential-access.md) |
| **`T1555.004`** | Community Technique | Execution | [Windows Service Secrets Storage](../tasks/administration/windows-service-secrets-storage.md) |
| **`T1556`** | Modify Authentication Process | Persistence, Defense Impairment, Credential Access | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Index](../detection/mitre-attack/index.md) · [Mfa Deletion](../detection/spl/mfa-deletion.md) |
| **`T1556.002`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1556.006`** | Multi-Factor Authentication | Persistence, Defense Impairment, Credential Access | [Index](../detection/mitre-attack/index.md) · [Mfa Deletion](../detection/spl/mfa-deletion.md) |
| **`T1557`** | Adversary-in-the-Middle | Credential Access, Collection | [Dns](../fundamentals/dns.md) · [Arp Spoofing](../fundamentals/concepts/arp-spoofing.md) · [Mac Address Spoofing](../fundamentals/concepts/mac-address-spoofing.md) · [Man In The Middle](../fundamentals/concepts/man-in-the-middle.md) *(+6 more)* |
| **`T1557.001`** | Name Resolution Poisoning and SMB Relay | Credential Access, Collection | [Llmnr Nbtns Poisoning](../detection/sigma/llmnr-nbtns-poisoning.md) |
| **`T1557.002`** | ARP Cache Poisoning | Credential Access, Collection | [Arp Spoofing](../fundamentals/concepts/arp-spoofing.md) · [Arp Spoofing Dai](../detection/sigma/arp-spoofing-dai.md) |
| **`T1558`** | Steal or Forge Kerberos Tickets | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Ad Kerberos Ldap Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md) · [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) *(+6 more)* |
| **`T1558.001`** | Golden Ticket | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1558.003`** | Kerberoasting | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Service Account Audit](../tasks/assurance/service-account-audit.md) · [Ad Kerberos Ldap Hardening](../tasks/hardening/ad-kerberos-ldap-hardening.md) · [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) *(+6 more)* |
| **`T1558.004`** | AS-REP Roasting | Credential Access | [Kerberos](../fundamentals/kerberos.md) · [Kerberoasting Asreproast Hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md) · [Kerberoasting](../fundamentals/concepts/kerberoasting.md) |
| **`T1562.002`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1562.004`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1564`** | Hide Artifacts | Stealth | [Exchange](../platforms/microsoft-365/exchange.md) · [File Systems](../fundamentals/concepts/file-systems.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1564.004`** | NTFS File Attributes | Stealth | [File Systems](../fundamentals/concepts/file-systems.md) |
| **`T1564.008`** | Email Hiding Rules | Stealth | [Exchange](../platforms/microsoft-365/exchange.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1566`** | Phishing | Initial Access | [Phishing Email Triage](../tasks/incident-response/phishing-email-triage.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) · [Social Engineering](../fundamentals/concepts/social-engineering.md) · [Index](../detection/mitre-attack/index.md) |
| **`T1566.001`** | Spearphishing Attachment | Initial Access | [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Hunting](../detection/s1ql/hunting.md) · [Windows Events](../detection/spl/windows-events.md) |
| **`T1567`** | Exfiltration Over Web Service | Exfiltration | [Persistence Hunting](../platforms/github/persistence-hunting.md) · [Anonymity Dark Web](../fundamentals/concepts/anonymity-dark-web.md) · [Privacy Laws](../fundamentals/concepts/privacy-laws.md) |
| **`T1567.002`** | Exfiltration to Cloud Storage | Exfiltration | [Threat Actor Profiles](../references/threat-actor-profiles.md) |
| **`T1569`** | System Services | Execution | [Services Daemons](../fundamentals/concepts/services-daemons.md) |
| **`T1569.002`** | Service Execution | Execution | [Services Daemons](../fundamentals/concepts/services-daemons.md) |
| **`T1573`** | Encrypted Channel | Command and Control | [Cryptography Fundamentals](../fundamentals/concepts/cryptography-fundamentals.md) |
| **`T1574`** | Hijack Execution Flow | Execution, Stealth | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Environment Variables And Path](../tasks/administration/environment-variables-and-path.md) · [Windows Service Accounts Least Privilege](../tasks/administration/windows-service-accounts-least-privilege.md) · [Filesystem](../platforms/linux/filesystem.md) *(+3 more)* |
| **`T1574.006`** | Dynamic Linker Hijacking | Execution, Stealth | [Filesystem](../platforms/linux/filesystem.md) |
| **`T1574.007`** | Path Interception by PATH Environment Variable | Execution, Stealth | [Environment Variables And Path](../tasks/administration/environment-variables-and-path.md) · [System Information](../platforms/windows/system-information.md) |
| **`T1574.009`** | Path Interception by Unquoted Path | Execution, Stealth | [Services](../platforms/windows/services.md) · [Services Daemons](../fundamentals/concepts/services-daemons.md) |
| **`T1574.010`** | Community Technique | Execution | [Windows Service Accounts Least Privilege](../tasks/administration/windows-service-accounts-least-privilege.md) |
| **`T1574.011`** | Community Technique | Execution | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Service Accounts Least Privilege](../tasks/administration/windows-service-accounts-least-privilege.md) |
| **`T1574.012`** | COR_PROFILER | Execution, Stealth | [System Information](../platforms/windows/system-information.md) |
| **`T1578.002`** | Create Cloud Instance | Defense Impairment | [Cloud Infrastructure Ephemeral Asset Hunting](../tasks/threat-hunting/cloud-infrastructure-ephemeral-asset-hunting.md) |
| **`T1584`** | Compromise Infrastructure | Resource Development | [Index](../detection/mitre-attack/index.md) |
| **`T1588`** | Obtain Capabilities | Resource Development | [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1588.003`** | Code Signing Certificates | Resource Development | [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1589`** | Gather Victim Identity Information | Reconnaissance | [Osint](../fundamentals/concepts/osint.md) |
| **`T1593`** | Search Open Websites/Domains | Reconnaissance | [Osint](../fundamentals/concepts/osint.md) |
| **`T1597`** | Search Closed Sources | Reconnaissance | [Anonymity Dark Web](../fundamentals/concepts/anonymity-dark-web.md) |
| **`T1598`** | Phishing for Information | Reconnaissance | [Social Engineering](../fundamentals/concepts/social-engineering.md) |
| **`T1600`** | Weaken Encryption | Defense Impairment | [Cryptographic Attacks](../fundamentals/concepts/cryptographic-attacks.md) · [Cryptography Fundamentals](../fundamentals/concepts/cryptography-fundamentals.md) |
| **`T1606`** | Forge Web Credentials | Credential Access | [Authentication Mfa Sso](../fundamentals/concepts/authentication-mfa-sso.md) · [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1606.002`** | SAML Tokens | Credential Access | [Authentication Mfa Sso](../fundamentals/concepts/authentication-mfa-sso.md) · [Digital Signatures](../fundamentals/concepts/digital-signatures.md) |
| **`T1610`** | Deploy Container | Execution | [Cloud Native Security](../fundamentals/concepts/cloud-native-security.md) |
| **`T1611`** | Escape to Host | Privilege Escalation | [Cloud Native Security](../fundamentals/concepts/cloud-native-security.md) |
| **`T1613`** | Container and Resource Discovery | Discovery | [Cloud Native Security](../fundamentals/concepts/cloud-native-security.md) |
| **`T1621`** | Multi-Factor Authentication Request Generation | Credential Access | [Authentication Mfa Sso](../fundamentals/concepts/authentication-mfa-sso.md) |
| **`T1648`** | Serverless Execution | Execution | [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) · [Persistence Hunting](../platforms/gcp/persistence-hunting.md) |
| **`T1649`** | Community Technique | Execution | [Credential Rotation After Compromise](../tasks/incident-response/credential-rotation-after-compromise.md) |
| **`T1651`** | Cloud Administration Command | Execution | [Compute](../platforms/aws/compute.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Compute](../platforms/azure/compute.md) · [Persistence Hunting](../platforms/azure/persistence-hunting.md) |
| **`T1657`** | Financial Theft | Impact | [Zero Knowledge Homomorphic Blockchain](../fundamentals/concepts/zero-knowledge-homomorphic-blockchain.md) |
| **`T1684`** | Social Engineering | Stealth | [Social Engineering](../fundamentals/concepts/social-engineering.md) |
| **`T1684.001`** | Impersonation | Stealth | [Social Engineering](../fundamentals/concepts/social-engineering.md) |
| **`T1685`** | Disable or Modify Tools | Defense Impairment | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Endpoint Edr Status](../tasks/assurance/endpoint-edr-status.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) *(+12 more)* |
| **`T1685.001`** | Disable or Modify Windows Event Log | Defense Impairment | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1685.002`** | Disable or Modify Cloud Log | Defense Impairment | [Threat Actor Profiles](../references/threat-actor-profiles.md) · [Audit Logging](../platforms/aws/audit-logging.md) · [Persistence Hunting](../platforms/aws/persistence-hunting.md) · [Audit Logging](../platforms/azure/audit-logging.md) *(+3 more)* |
| **`T1685.004`** | Disable or Modify Linux Audit System Log | Defense Impairment | [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) |
| **`T1685.005`** | Clear Windows Event Logs | Defense Impairment | [Index](../detection/mitre-attack/index.md) · [Windows Events](../detection/spl/windows-events.md) |
| **`T1686`** | Disable or Modify System Firewall | Defense Impairment | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) |
| **`T1688`** | Safe Mode Boot | Defense Impairment | [Windows Registry Security Keys](../references/windows-registry-security-keys.md) · [Windows Cis Attack Surface Reduction](../tasks/hardening/windows-cis-attack-surface-reduction.md) · [Boot Startup Sequence](../fundamentals/concepts/boot-startup-sequence.md) |
| **`T1689`** | Downgrade Attack | Defense Impairment | [Powershell](../detection/spl/powershell.md) |
| **`T1690`** | Prevent Command History Logging | Defense Impairment | [Shell Command History](../tasks/administration/shell-command-history.md) · [Adversary Emulation Profiling](../tasks/threat-intelligence/adversary-emulation-profiling.md) |

---

## 3. Automated Validation & CI Pipeline

This coverage matrix is dynamically maintained by `tools/validate_mitre.py`. Any new detection query, incident response playbook, or hardening configuration tagged with an ATT&CK ID is automatically validated against the enterprise taxonomy during CI verification.
