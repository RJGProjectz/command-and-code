---
title: Offensive
type: index
hide:
  - toc
---

# Offensive Security — Assessment & Enumeration

Authorized offensive work: finding the weaknesses in a system **before** an attacker does, so they
can be fixed. These pages are the practical, tool-driven counterpart to the offensive **theory** that
already lives in [Concepts](../fundamentals/concepts/index.md) and the defensive controls in
[Web Applications & OWASP](../fundamentals/web-apps/owasp-web-top-10.md).

> [!WARNING]
> **Authorized testing only.** Every technique here generates traffic against a target. Run them
> **only** against systems you own or have explicit, written permission to test (a signed engagement,
> a scoped bug-bounty program, or your own lab). Unauthorized scanning and enumeration may be illegal
> — see [Cyber Law](../fundamentals/concepts/cyber-law.md) and
> [Ethical Hacking & Ethics](../fundamentals/concepts/ethical-hacking.md). Stay inside the agreed
> scope, rate, and time window, and keep an audit trail of what you ran.

## The red-team lifecycle — by stage

This track is organised by the **five stages of an authorized red-team engagement**, the offensive
mirror of the Defensive tab's categories. Because this project is **assessment/enumeration-only**, the
stages that turn weaponized in a real intrusion — exploitation, Command-and-Control, exfiltration — are
documented as **what to know and how to detect/harden**, never as attack tooling, implants or payloads.

### Stage 1 — Reconnaissance
*Gather OSINT, map the estate, and scan networks and public/internal entry points — passively first.*

- [Map an Organization's Attack Surface with OSINT and Active Reconnaissance](osint-active-recon.md) · [Passive Web OSINT Tool](passive-web-osint.md) · [Enumerate an Internal Network and its Services](network-infrastructure-enumeration.md) · [Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness](wifi-wireless-assessment.md) · [Enumerate Cloud Attack Surface across AWS, Azure and GCP](cloud-attack-surface-enumeration.md)
- **Theory:** [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Packet Sniffing](../fundamentals/concepts/packet-sniffing.md) · [Wi-Fi Security](../fundamentals/concepts/wifi-security.md)

### Stage 2 — Initial Access
*Find and validate the ways in — exposed services, web/API weaknesses, weak credentials, people.*

- [Enumerate a Web Application for Technology, Versions and Weaknesses](web-application-assessment.md) · [Assess an LLM Application for Prompt Injection and Abuse](llm-application-assessment.md)
- **Theory:** [Social Engineering](../fundamentals/concepts/social-engineering.md) · [Password Attacks](../fundamentals/concepts/password-attacks.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md)
- **Scope:** we document how to *identify* initial-access vectors; weaponized exploit payloads stay out of scope and inside a scoped engagement.
- **Planned (WP-87):** Web API assessment (REST/GraphQL, authz/IDOR), password attacks & cracking, phishing/social-engineering ops (payload-free), mobile app assessment.

### Stage 3 — Foothold & Command-and-Control (C2)
*How an attacker persists and calls home — **covered for awareness and defense, not operation.***

- This project does **not** publish C2 frameworks, implants, or persistence tooling (enumeration/assessment-only).
- **Know it:** [Malware Types & Analysis](../fundamentals/concepts/malware-types-analysis.md) · [Anonymity & the Dark Web](../fundamentals/concepts/anonymity-dark-web.md)
- **Detect it:** [Scheduled-Task Persistence Review](../tasks/threat-hunting/scheduled-task-persistence-review.md) · [LOLBins Execution Hunting](../tasks/threat-hunting/lolbins-execution-hunting.md)
- **Harden it:** [AppLocker Application Control](../tasks/hardening/applocker-deployment-rollout.md) · [ASR & Credential Guard](../tasks/hardening/windows-cis-attack-surface-reduction.md)

### Stage 4 — Lateral Movement & Privilege Escalation
*Move deeper and escalate — assessed by enumerating the paths that make it possible.*

- [Enumerate a Windows Host and Identify Privilege-Escalation Paths](windows-host-enumeration-privesc.md) · [Enumerate a Linux Host and Identify Privilege-Escalation Paths](linux-host-enumeration-privesc.md) · [Enumerate Active Directory for Users, Privileges and Attack Paths](active-directory-enumeration.md)
- **Theory:** [Kerberoasting](../fundamentals/concepts/kerberoasting.md) · [Credential Dumping](../fundamentals/concepts/credential-dumping.md) · [Man-in-the-Middle](../fundamentals/concepts/man-in-the-middle.md)
- **Detect it:** [Lateral Movement (SMB)](../detection/spl/lateral-movement-smb.md) · [Kerberoasting / AS-REP Roast Hunting](../tasks/threat-hunting/kerberoasting-asreproast-hunting.md)
- **Planned (WP-87):** post-exploitation / lateral-movement recon workflow (situational awareness, trust mapping).

### Stage 5 — Actions on Objective & Reporting
*Reach the goal (data-access **simulation**) and deliver the remediation report — the point of the engagement.*

- **Reporting theory:** [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md)
- **Scope:** impact is *simulated and evidenced*, not operational — no data-theft or exfiltration tooling.
- **Planned (WP-87):** engagement reporting workflow + an enumeration-findings → NDJSON normaliser (one shared evidence schema across the tools).

## Pages

<!-- cc:index tasks="Assessment" -->
| Entry | Type | Platforms | Languages | Tasks |
| --- | --- | --- | --- | --- |
| [Assess a Web API for Endpoints, Authorization Flaws and Abuse](web-api-assessment.md) | Workflow | Linux | Bash, HTTP | Assessment |
| [Assess a Wi-Fi Network's Posture — Survey, Encryption and Rogue-AP Awareness](wifi-wireless-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Assess an LLM Application for Prompt Injection and Abuse](llm-application-assessment.md) | Workflow | Linux | Python, HTTP | Assessment |
| [Enumerate a Linux Host and Identify Privilege-Escalation Paths](linux-host-enumeration-privesc.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Web Application for Technology, Versions and Weaknesses](web-application-assessment.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate a Windows Host and Identify Privilege-Escalation Paths](windows-host-enumeration-privesc.md) | Workflow | Windows | PowerShell | Assessment |
| [Enumerate Active Directory for Users, Privileges and Attack Paths](active-directory-enumeration.md) | Workflow | Active Directory, Windows | PowerShell, Bash | Assessment |
| [Enumerate an Internal Network and its Services](network-infrastructure-enumeration.md) | Workflow | Linux | Bash | Assessment |
| [Enumerate Cloud Attack Surface across AWS, Azure and GCP](cloud-attack-surface-enumeration.md) | Workflow | AWS, Azure, GCP | Bash, Python | Assessment |
| [Map an Organization's Attack Surface with OSINT and Active Reconnaissance](osint-active-recon.md) | Workflow | Linux | Bash | Assessment |
| [API Surface Recon Tool (scope- and rate-limit-aware)](api-surface-recon-tool.md) | Tool | Linux | Bash | Assessment |
| [Passive Web OSINT Tool (one or many targets)](passive-web-osint.md) | Tool | Linux | Bash | Assessment |

<!-- /cc:index -->

## Related reading

- **Theory:** [Penetration Testing & Red Teaming](../fundamentals/concepts/penetration-testing.md) · [OSINT & Reconnaissance](../fundamentals/concepts/osint.md) · [Port Scanning](../fundamentals/concepts/port-scanning.md) · [Vulnerability Assessment & Patch Management](../fundamentals/concepts/vulnerability-management.md)
- **Defensive counterparts:** [OWASP Top 10 for Web Applications](../fundamentals/web-apps/owasp-web-top-10.md) · [HTTP Security Headers](../fundamentals/web-apps/http-security-headers.md)
- **Detect it:** the [Detection](../detection/index.md) tab holds the queries and rules that catch scanning and enumeration against your own estate.
