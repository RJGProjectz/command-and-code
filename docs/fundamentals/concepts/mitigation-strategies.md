---
title: Security Mitigation Strategies
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, Bash, Python]
tasks: [Hardening, Governance, Detection Engineering]
category: Defensive Security
security_domain: Operations
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, mitigation, defense, countermeasure, hardening, remediation, patch-management, defense-in-depth]
aliases: [countermeasures, security controls, defensive measures, compensating controls, threat mitigation]
difficulty: intermediate
verified: false
---

# Security Mitigation Strategies
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a mitigation strategy is a planned, deliberate action — technical control, process change, or architectural decision — that reduces the probability or impact of a security threat.

## What it is

Mitigations are the operational answer to risk assessments and threat models. Where a threat model identifies *what* can go wrong, mitigations define *what to do about it*. The goal is not to eliminate all risk (that is impossible) but to reduce it to an acceptable level within budget and operational constraints [Adversarial AI Attacks, Mitigations and Defense Strategies, p. 494; CEH v12 Study Guide, p. 65].

Mitigations are classified by function and by timing:

- **Preventive** — block an attack before it succeeds (firewalls, authentication, input validation)
- **Detective** — identify an attack while it is in progress (IDS/IPS, SIEM alerts, honeypots)
- **Corrective** — reduce damage after an attack (incident response, backups, containment)
- **Compensating** — reduce residual risk when a primary control cannot be implemented (network segmentation when patching a legacy system is impossible)

The layering of multiple mitigation types is what security practitioners call **defense in depth** — no single control is a silver bullet, but the combination raises the cost of a successful attack beyond what most adversaries will invest [Web Application Security, 2nd ed., p. 31].

## How it works

### Risk-based prioritization

Mitigations should be prioritized by the risk they address, not by ease of implementation or vendor marketing. A risk-based approach orders controls by multiplying likelihood × impact, then addresses the highest-scoring threats first. This prevents teams from spending effort on theoretical edge cases while critical exposures remain open [Adversarial AI Attacks, Mitigations and Defense Strategies, p. 503].

**Common prioritization frameworks:**

| Framework | Approach |
| :--- | :--- |
| **CVSS base score** | Scores vulnerability severity 0–10; use to prioritize patch cycles |
| **MITRE ATT&CK mitigations** | Maps each technique to a named mitigation (e.g., M1026 Privileged Account Management) |
| **CIS Controls** | Ordered list of controls weighted by effectiveness vs. implementation cost |
| **NIST SP 800-30** | Risk assessment guide linking threats → vulnerabilities → mitigations |

### Technical mitigations

Technical mitigations operate at the system, network, or application layer without requiring user action:

**Patch management** is the highest-ROI mitigation for most organizations. The majority of exploited vulnerabilities are addressed by vendor patches before exploitation becomes widespread — the window between patch release and mass exploitation (the *n-day* window) has shortened to days or hours for high-severity CVEs. Automated patch pipelines reduce dwell time.

**Network segmentation** limits lateral movement. An attacker who compromises a workstation should not have unrestricted access to production databases or domain controllers. Segmentation using VLANs, micro-segmentation (zero-trust network access), and host-based firewalls contains the blast radius.

**Principle of least privilege** ensures identities — users, service accounts, and applications — hold only the permissions required for their function. Overly permissive accounts are a force-multiplier for attackers.

**Input validation and output encoding** prevent injection attacks (SQL injection, XSS, command injection) at the application layer, stopping entire classes of exploits before they interact with backend systems.

**Multi-factor authentication (MFA)** mitigates credential theft and password-spray attacks. Even if an attacker obtains a password, they cannot authenticate without the second factor.

```powershell
# Check whether MFA is enforced for all Entra ID users (requires Graph)
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgPolicyAuthenticationMethodPolicy | Select-Object -ExpandProperty AuthenticationMethodConfigurations |
  Where-Object { $_.State -eq "disabled" } |
  Select-Object Id, State
```

> [!CAUTION]
> Mitigations that restrict authentication (disabling legacy protocols, enforcing MFA) can break existing integrations. Always test in a non-production environment and have a rollback plan before applying to production systems.

### Compensating controls

When a primary mitigation is infeasible (a legacy system that cannot be patched, a business process that requires broad access), a **compensating control** reduces residual risk:

- **Network isolation** — place the unpatched system on a dedicated VLAN with strict firewall rules
- **Enhanced monitoring** — apply aggressive logging and alerting to activity on the vulnerable system
- **Supplementary authentication** — require jump-host access for all administrative sessions
- **Restrict exploitability** — disable the specific service or feature the vulnerability targets, if business operations allow

Document compensating controls formally as accepted risk with a named risk owner and scheduled review date [Adversarial AI Attacks, Mitigations and Defense Strategies, p. 494].

### Process and administrative mitigations

Administrative controls reduce risk through policy and human behaviour:

- **Security awareness training** — users who recognise phishing emails remove a primary initial-access vector
- **Change management** — controlled change windows prevent misconfigurations introduced by unreviewed changes
- **Incident response planning** — a tested IR plan converts a potential breach into a contained incident
- **Vendor management** — third-party risk assessments prevent supply-chain compromise vectors

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | Mitigations index: [https://attack.mitre.org/mitigations/](https://attack.mitre.org/mitigations/) — each technique links to its recommended controls |
| **What it prevents** | Left unmitigated, known vulnerabilities are exploited by automated tooling within hours of disclosure |
| **Regulatory drivers** | ISO/IEC 27001 Annex A, NIST CSF Protect function, CIS Critical Security Controls |
| **Where defenders meet it** | Vulnerability management programs, penetration test remediation cycles, post-incident reviews |

Risk that is documented as accepted without mitigation is not a mitigated risk — it is an unmitigated risk with a paper trail. Mitigations must be implemented and verified, not just planned [Adversarial AI Attacks, Mitigations and Defense Strategies, p. 503].

## Do it

Enumerate unpatched vulnerabilities on a Windows host:

```powershell
# List missing Windows patches using the Windows Update API
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$Searcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $Searcher.Search("IsInstalled=0")
$SearchResult.Updates | Select-Object Title, MsrcSeverity
```

Check for accounts with excessive AD permissions:

```powershell
# Find accounts with AdminCount=1 (were once in privileged groups)
Get-ADUser -Filter { AdminCount -eq 1 } -Properties AdminCount, Enabled |
  Select-Object SamAccountName, Enabled, AdminCount |
  Sort-Object SamAccountName
```

Verify network segmentation from a Linux host:

```bash
# Test reachability to a sensitive network segment (should be blocked)
nmap -Pn --open -p 445,3389,1433 10.100.0.0/24 2>/dev/null | grep -E "open|report"
```

## See it

Evidence that mitigations are absent or insufficient:

| Source | What you see |
| :--- | :--- |
| Windows Event log | Accounts authenticating with NTLM (Event 4776) despite MFA policy |
| Nessus / OpenVAS scan results | Critical CVEs with CVSS ≥ 9 on internet-facing hosts |
| Active Directory | Service accounts with Domain Admin membership |
| Firewall logs | Workstations directly reaching database servers on port 1433/3306 |
| SIEM alert backlog | Identical detection rules firing repeatedly without remediation closures |

## Detect it

- Detection: [Detection Engineering workflows](../../tasks/detection-engineering/index.md) — build rules that surface evidence mitigation controls are bypassed
- Cross-reference: [Defense in Depth](defense-in-depth.md), [Risk Management and Governance](risk-management-governance.md), [Security Controls](security-controls.md), [Vulnerability Management](vulnerability-management.md)

---
*Sources: Adversarial AI Attacks, Mitigations and Defense Strategies (Packt, 2024), p. 494, 503; CEH v12 Study Guide (McGraw-Hill, 2023), p. 65; Web Application Security, 2nd ed. (O'Reilly, 2024), p. 31.*
