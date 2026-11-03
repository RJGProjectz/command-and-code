---
title: Security Controls
type: concept
platforms: [Windows, Linux]
languages: [PowerShell, KQL]
tasks: [Hardening, Administration, Detection Engineering, Assessment]
category: Security Operations
security_domain: Operations
author: RJGProjectz
date_created: 2026-11-03
last_updated: 2026-11-03
tags: [security-controls, preventive, detective, corrective, deterrent, compensating, defense-in-depth, NIST-CSF, CIS-Controls, technical-controls, administrative-controls, physical-controls, risk-mitigation]
aliases: [security controls, preventive controls, detective controls, corrective controls, compensating controls, deterrent controls, countermeasures, safeguards]
difficulty: basic
verified: false
---

# Security Controls
> **Created**: 2026-11-03T00:00:00Z
> **Last Modified**: 2026-11-03T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** security controls are the safeguards — technical, administrative, and physical — that an organization implements to reduce the likelihood or impact of a security threat exploiting a vulnerability.

## What it is

A security control is any measure that reduces risk to an asset. The primary goal is to protect the confidentiality, integrity, and availability of information systems. Controls do not eliminate risk entirely; they reduce the probability of an incident or limit its damage when one occurs.

Controls are selected and calibrated based on a risk assessment: the value of the asset being protected, the likelihood of a threat, and the cost of the control. A control whose cost exceeds the value of the asset it protects is generally not worth implementing.

Controls come in three implementation types:

| Type | Description | Examples |
| :--- | :--- | :--- |
| **Technical (logical)** | Enforced by software or hardware | Firewalls, MFA, encryption, IDS/IPS, endpoint agents |
| **Administrative (operational)** | Enforced through policy and process | Security awareness training, access review procedures, change management |
| **Physical** | Enforced in the built environment | Keycards, mantraps, locks, server room access control, surveillance cameras |

## How it works

Controls are classified by their **function** — what they do when a threat arrives:

### Preventive Controls

Preventive controls stop an incident from occurring or reduce its likelihood. They are the first line of defense and operate before any compromise takes place.

Examples:
- **Technical:** firewalls blocking prohibited traffic; antivirus / EDR blocking malicious executables; MFA preventing unauthorized login with stolen credentials; patch management eliminating known vulnerabilities
- **Administrative:** security awareness training that reduces successful phishing; vendor management policies that restrict supply-chain access; least-privilege access provisioning
- **Physical:** server room badge access preventing physical tampering; cable locks on workstations; visitor escort policies

### Detective Controls

Detective controls identify that an incident has occurred or is occurring. They cannot prevent a breach, but they shorten the time between compromise and discovery — a critical factor because dwell time (how long an attacker goes undetected) directly determines the severity of the impact.

Examples:
- **Technical:** SIEM correlation rules; intrusion detection systems (IDS); log monitoring; file integrity monitoring; anomaly-based network analysis
- **Administrative:** internal audits discovering excess access rights; quarterly access reviews flagging orphaned accounts; compliance scanning
- **Physical:** CCTV camera footage; motion sensors; door alarms on unauthorized access

### Corrective Controls

Corrective controls restore a system to a secure state after an incident. They work after the breach has been detected.

Examples: incident response playbooks; backup and restore systems; patch deployment after a vulnerability is exploited; revocation of compromised credentials; network isolation procedures.

### Deterrent Controls

Deterrent controls discourage attackers by increasing the perceived risk or effort required to attack successfully.

Examples: warning banners at login ("unauthorized access is monitored and prosecuted"); visible security cameras; published penetration testing programmes; the presence of a Security Operations Center (SOC).

Note: deterrent controls have limited effect on determined adversaries (nation-state actors, ransomware groups). They are most effective against opportunistic attackers.

### Compensating Controls

A compensating control is applied when a primary control cannot be implemented — typically due to technical constraints, operational impact, or cost. It provides an equivalent level of protection through an alternative means.

Example: if an organization cannot patch a legacy manufacturing control system (the patch would require an extended outage), it might implement network segmentation and enhanced monitoring as compensating controls.

## Why it matters

| | |
| :--- | :--- |
| **Framework alignment** | CIS Critical Security Controls v8, NIST Cybersecurity Framework (CSF), ISO/IEC 27001 Annex A, NIST SP 800-53, PCI DSS |
| **What it enables** | Systematic, evidence-based security — controls are inventoried, tested, and mapped to risks rather than applied ad hoc |
| **Where defenders meet it** | Risk assessments, compliance audits, security architecture reviews, pen test remediation, and continuous control monitoring |

## Defense in Depth

Defense in Depth (DiD) is the principle of layering multiple controls across different tiers so that a failure in one layer does not result in a complete breach. Originally developed by the NSA for protecting critical national infrastructure, the model organizes controls around:

- **Perimeter security** — firewalls, IPS, DMZ design
- **Network security** — segmentation, VLANs, NAC
- **Endpoint security** — EDR, application control, patch management
- **Application security** — input validation, WAF, secure coding
- **Data security** — encryption, DLP, access controls on storage

Each layer is designed so that an attacker who defeats one control still faces additional barriers. No organization can be adequately protected by a single control layer.

→ [Defense in Depth and Secure Network Design](defense-in-depth.md)

## Do it

Audit Windows security control coverage on a local host:

```powershell
# Check Windows Firewall state across all profiles
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Check Windows Defender status
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled

# List local users and their group memberships
Get-LocalUser | Where-Object Enabled -eq $true | ForEach-Object {
    $u = $_
    [PSCustomObject]@{
        User = $u.Name
        Groups = (Get-LocalGroup | Where-Object { $u.SID -in (Get-LocalGroupMember $_ -ErrorAction SilentlyContinue).SID })
    }
}
```

Enumerate CIS Benchmark compliance gaps:

```powershell
# Install the LGPO tool or use CISCATLite for scored audits
# Manual: verify Account Lockout Policy
Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow
```

## See it

| Source | What you see |
| :--- | :--- |
| SIEM alert volume | A drop in detective control coverage — if alerts fall to zero, detection may be broken |
| Vulnerability scanner output | Which preventive controls (patches, configs) are missing |
| Compliance report | Control pass/fail against a framework (CIS, NIST) |
| Pen test report | Controls that failed to prevent or detect the tester's actions |

## Detect it

- Assurance: [Security Assurance and Review](../../tasks/assurance/index.md)
- Detection Engineering: [Detection Engineering tasks](../../tasks/detection-engineering/index.md)
- Harden: [Hardening tasks](../../tasks/hardening/index.md)

## Related concepts

- [Defense in Depth and Secure Network Design](defense-in-depth.md)
- [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- [CIA Triad and Least Privilege](cia-triad.md)
- [Zero Trust Architecture](zero-trust.md)
- [Threat Modeling](threat-modeling.md)
- [Security Information and Event Management (SIEM)](siem.md)
- [Vulnerability Assessment and Patch Management](vulnerability-management.md)

## External Resources

- [CIS Critical Security Controls v8](https://www.cisecurity.org/controls/v8)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST SP 800-53 Rev 5: Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [ISO/IEC 27001:2022 — Annex A Controls](https://www.iso.org/standard/27001)
- [PCI DSS v4.0 Requirements and Testing Procedures](https://www.pcisecuritystandards.org/)
