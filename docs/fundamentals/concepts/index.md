---
title: Concepts
type: index
---

# Concepts
> **Created**: 2026-10-11T22:00:00Z
> **Last Modified**: 2026-10-11T22:00:00Z
> **Author**: RJGProjectz

Short pages that explain one security idea in plain words and then bridge to the work. Every concept ends the same way:

- **Do it** — the `cc` CLI commands and safe checks to run on a host you own
- **See it** — what it looks like in logs, telemetry and packets
- **Detect it** — links to our detections, hunts, response workflows and hardening tasks

## Operating systems

How Windows and Linux work underneath the commands, side by side — the base the security concepts build on:

| Concept | Windows | Linux |
| :--- | :--- | :--- |
| [File systems](file-systems.md) | NTFS, MFT, ACLs, alternate data streams | ext4/XFS, inodes, mode bits, POSIX ACLs |
| [Processes, threads and handles](processes-threads.md) | PID/PPID, access tokens, handles | PID/PPID, UIDs and capabilities, file descriptors |
| [Windows registry](windows-registry.md) | hives, Run keys, Services key | `/etc` and dot files instead |
| [Services and daemons](services-daemons.md) | Service Control Manager, service accounts | systemd units, `User=`, sandboxing |
| [Users, groups and privilege](users-groups-permissions.md) | SIDs, Administrators, UAC | UIDs, root, sudo, setuid |
| [Boot and startup sequence](boot-startup-sequence.md) | UEFI → bootmgr → winload → smss → logon | UEFI → GRUB → kernel + initramfs → systemd |

Deeper internals: [Windows process internals](../systems/windows-processes.md) · [Memory internals and paging](../systems/memory-internals.md) ·
[UEFI and Secure Boot](../systems/uefi-secure-boot.md) · [AppLocker](../systems/applocker.md) · [Sysmon](../systems/sysmon.md) ·
[Cross-platform data handling](../systems/cross-platform-data-handling.md).

New concepts start from [`templates/concept.md`](https://github.com/RJGProjectz/command-and-code/blob/main/templates/concept.md).

<!-- cc:index type="concept" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Access Control Models (ACL, DAC, MAC, RBAC, ABAC)](access-control-models.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Administration, Assurance |
| [Anonymity Networks and the Dark Web (Tor, I2P, Tails)](anonymity-dark-web.md) | Concept | Windows, Linux, Microsoft Defender | KQL, PowerShell, Bash | Threat Intelligence, Threat Hunting, Investigation |
| [ARP Spoofing](arp-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [Authentication, MFA, SSO and Federation](authentication-mfa-sso.md) | Concept | Windows, Entra ID, Microsoft 365 | PowerShell, KQL | Investigation, Hardening, Incident Response |
| [Boot and Startup Sequence (UEFI to Logon)](boot-startup-sequence.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Troubleshooting |
| [CIA Triad and Least Privilege](cia-triad.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance |
| [Cloud-Native Security (Containers, Kubernetes, Microservices)](cloud-native-security.md) | Concept | Linux, Azure | Bash, KQL | Hardening, Threat Hunting, Assurance |
| [Credential Dumping](credential-dumping.md) | Concept | Windows, Microsoft Defender, Active Directory | PowerShell, KQL | Incident Response, Threat Hunting, Hardening |
| [Cryptographic Attacks and Cryptanalysis](cryptographic-attacks.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Threat Hunting, Hardening, Assurance |
| [Cryptography Fundamentals (Symmetric and Asymmetric Encryption)](cryptography-fundamentals.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Cyber Law (CFAA, ECPA, FISA, PATRIOT Act, SOX, FISMA, FedRAMP)](cyber-law.md) | Concept | Windows, Azure | PowerShell | Compliance, Assurance, Incident Response |
| [Defense in Depth and Secure Network Design](defense-in-depth.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Hardening, Assurance |
| [Denial of Service (DoS and DDoS)](denial-of-service.md) | Concept | Windows, Linux, Azure | PowerShell, Bash | Incident Response, Troubleshooting, Hardening |
| [Digital Forensics and Incident Response (DFIR)](digital-forensics.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Incident Response, Investigation |
| [Digital Signatures and Non-repudiation (RSA, DSA, ECDSA, EdDSA, PGP)](digital-signatures.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Forensics |
| [Ethical Hacking, Ethics and Careers](ethical-hacking.md) | Concept | Windows, Linux | PowerShell, Bash | Assurance, Hardening |
| [File Systems (NTFS, ext4, XFS)](file-systems.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Hardening |
| [Hash Functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2)](hash-functions.md) | Concept | Windows, Linux | PowerShell, Bash | Forensics, Investigation, Threat Intelligence |
| [Identity and Access Management (IAM, PAM, Directory Services)](identity-access-management.md) | Concept | Windows Server, Entra ID, Azure | PowerShell, KQL | Administration, Hardening, Assurance |
| [Intrusion Detection and Prevention (IDS/IPS)](ids-ips.md) | Concept | Linux, Windows, Microsoft Defender | Bash, KQL | Detection Engineering, Threat Hunting, Hardening |
| [Kerberoasting](kerberoasting.md) | Concept | Active Directory, Windows Server, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Investigation |
| [MAC Addresses and Spoofing](mac-address-spoofing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Troubleshooting |
| [Malware Types and Analysis (Spyware, RATs, Rootkits)](malware-types-analysis.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Incident Response, Forensics, Threat Intelligence |
| [Man-in-the-Middle Attacks](man-in-the-middle.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Mobile Device and Application Security](mobile-security.md) | Concept | Intune, Microsoft 365 | PowerShell, KQL | Hardening, Assurance, Investigation |
| [OSI Model and TCP](osi-model-tcp.md) | Concept | Windows, Linux | PowerShell, Bash | Troubleshooting, Investigation |
| [OSINT and Reconnaissance](osint.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |
| [Packet Sniffing](packet-sniffing.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Troubleshooting, Threat Hunting |
| [Password Attacks and Defences (Spraying, Cracking, Wordlists)](password-attacks.md) | Concept | Windows, Entra ID, Microsoft Defender | PowerShell, KQL | Threat Hunting, Hardening, Incident Response |
| [Penetration Testing and Red Teaming (Methodology and Detection)](penetration-testing.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Assurance, Threat Hunting, Detection Engineering |
| [Port Scanning](port-scanning.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Investigation, Threat Hunting, Hardening |
| [Post-Quantum Cryptography (ML-KEM, ML-DSA, SLH-DSA)](post-quantum-cryptography.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Assurance, Administration |
| [Privacy Laws and Data Protection (GDPR, CCPA, HIPAA)](privacy-laws.md) | Concept | Microsoft 365, Windows | PowerShell, KQL | Compliance, Incident Response, Assurance |
| [Processes, Threads and Handles](processes-threads.md) | Concept | Windows, Linux | PowerShell, Bash | Incident Response, Investigation, Threat Hunting |
| [Proxy Servers](proxy-servers.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Administration |
| [Quantum Computing and Security (Qubits, QKD)](quantum-computing-security.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Assurance |
| [Ransomware](ransomware.md) | Concept | Windows, Linux, VMware, SentinelOne | PowerShell, S1QL | Incident Response, Threat Hunting, Hardening |
| [Risk Management, Policies and Compliance Audits](risk-management-governance.md) | Concept | Windows, Linux | PowerShell | Assurance, Compliance |
| [Secure SDLC, DevSecOps and Secure Coding](secure-sdlc-devsecops.md) | Concept | Windows, Linux | PowerShell, Bash, Python | Hardening, Assurance, Automation |
| [Security Information and Event Management (SIEM)](siem.md) | Concept | Splunk, Microsoft Defender, Azure | SPL, KQL | Detection Engineering, Investigation, Threat Hunting |
| [Security Standards Map (ISO/IEC 27000 series, NIST SP 800)](security-standards-map.md) | Concept | Windows, Linux, Azure | PowerShell | Compliance, Assurance, Hardening |
| [Services and Daemons (Windows SCM, systemd)](services-daemons.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Threat Hunting, Hardening |
| [Social Engineering (Phishing, Vishing, Pretexting, Tailgating)](social-engineering.md) | Concept | Microsoft 365, Exchange Online, Microsoft Defender | KQL, PowerShell | Incident Response, Investigation, Hardening |
| [Surveillance, Counter-Surveillance and Deception](surveillance-deception.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, KQL | Threat Hunting, Detection Engineering, Investigation |
| [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md) | Concept | Windows, Microsoft Defender | KQL, PowerShell | Threat Intelligence, Threat Hunting, Detection Engineering |
| [Users, Groups and Privilege (SIDs, UIDs, UAC, sudo)](users-groups-permissions.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Hardening, Incident Response |
| [Vulnerability Assessment and Patch Management](vulnerability-management.md) | Concept | Windows, Linux, Microsoft Defender | PowerShell, Bash, KQL | Hardening, Assurance, Administration |
| [Wi-Fi Deauthentication and Rogue Access Points](wifi-deauth-rogue-ap.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Hunting, Investigation, Hardening |
| [Wi-Fi Security (WEP, WPA, WPA2, WPA3)](wifi-security.md) | Concept | Windows, Linux | PowerShell, Bash, Windows CLI | Hardening, Investigation, Assurance |
| [Windows Registry (and the Linux /etc Equivalent)](windows-registry.md) | Concept | Windows, Linux | PowerShell, Bash | Investigation, Forensics, Threat Hunting |
| [WPA/WPA2 Passphrase Attacks (Handshake Capture)](wifi-passphrase-attacks.md) | Concept | Windows, Linux | PowerShell, Bash | Hardening, Investigation, Threat Hunting |
| [Zero-Knowledge Proofs, Homomorphic Encryption and Blockchain](zero-knowledge-homomorphic-blockchain.md) | Concept | Windows, Linux | PowerShell, Bash | Threat Intelligence, Investigation |

<!-- /cc:index -->
