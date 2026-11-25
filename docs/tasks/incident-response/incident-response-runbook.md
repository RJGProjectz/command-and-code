---
title: Building an Incident Response Runbook
type: workflow
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, Bash]
tasks: [Incident Response]
category: Workflow
security_domain: Operations
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [workflow, incident-response, runbook, playbook, raci, ir-plan, hybrid-cloud]
aliases: [IR runbook, incident response playbook, security incident workflow, hybrid cloud IR]
difficulty: intermediate
verified: false
# last_verified:
---

# Building an Incident Response Runbook
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> This workflow contains investigation and response steps. Before running any action:
> 1. Ensure you have authorised scope and incident ticket approval.
> 2. Validate state-changing actions with `-WhatIf` / `--whatif`.
> 3. Document all actions and findings in the incident ticket.

**Trigger:** a security incident has been detected or declared, and the team needs a structured procedure to execute the response consistently across hybrid cloud and on-premises environments.

**Goal:** a written runbook that any on-call analyst can execute from declaration to closure — removing ambiguity under pressure, enforcing consistent evidence collection, and meeting regulatory notification obligations.

## 1. What a runbook is

A runbook is a documented, step-by-step procedure for a specific incident type. It differs from a *plan* (high-level strategy) and a *policy* (rules and principles) in that it is **operational** — it tells you exactly which commands to run, in what order, with what approval checkpoints, and who is responsible for each action.

An effective runbook has five properties: it is specific to one incident type, it is written at the analyst's reading level, it references the systems and tools your organisation actually has, it includes RACI for each major decision point, and it is tested (tabletop or live drill) before it is needed. [Security Architecture for Hybrid Cloud, pp. 357–372]

## 2. Runbook phases

Every runbook follows the same six phases regardless of incident type. The content within each phase is specific to the scenario.

```
Detect → Triage → Contain → Eradicate → Recover → Review
```

| Phase | Key outputs | Approvals typically needed |
| :---- | :---------- | :------------------------- |
| **Detect** | Alert validated, incident ticket opened, severity assigned | Team lead notified |
| **Triage** | Scope defined, affected systems listed, evidence preserved | Incident commander |
| **Contain** | Isolation or blocking actions taken, spread stopped | CISO / change control |
| **Eradicate** | Root cause removed, all IOCs cleared from environment | Change control |
| **Recover** | Systems restored, monitoring increased, comms sent | Business owner |
| **Review** | Timeline written, lessons learned documented, runbook updated | CISO / leadership |

## 3. First step — declare and scope

The first analyst to respond confirms the incident is real (not a false positive), opens the ticket, assigns an initial severity, and notifies the incident commander.

→ [Endpoint Triage](endpoint-triage.md) · [Phishing Email Triage](phishing-email-triage.md) · [Account Compromise](account-compromise.md)

Severity tiers (adapt to your organisation's definitions):

| Severity | Criteria | Initial response SLA |
| :------- | :------- | :------------------- |
| **P1 — Critical** | Active breach, ransomware, data leaving the network | 15 minutes |
| **P2 — High** | Confirmed compromise, contained to one system | 1 hour |
| **P3 — Medium** | Suspicious activity, unconfirmed breach | 4 hours |
| **P4 — Low** | Policy violation, no evidence of compromise | Next business day |

## 4. Collect evidence before touching anything

Evidence must be preserved before any containment action changes system state. Minimum artefacts to collect from an affected endpoint:

```powershell
# Capture running processes, network connections, and scheduled tasks
Get-Process | Export-Csv "$env:TEMP\ir-processes.csv" -NoTypeInformation
Get-NetTCPConnection | Export-Csv "$env:TEMP\ir-netconn.csv" -NoTypeInformation
Get-ScheduledTask | Where-Object State -ne Disabled | Export-Csv "$env:TEMP\ir-tasks.csv" -NoTypeInformation

# Collect recent Security events (adjust -MaxEvents for your environment)
Get-WinEvent -LogName Security -MaxEvents 2000 |
    Export-Csv "$env:TEMP\ir-security-events.csv" -NoTypeInformation
```

> [!CAUTION]
> **SECURITY WARNING**: Acquire volatile evidence (memory, running processes, active connections) before isolating or rebooting a system. Rebooting destroys in-memory artefacts and may erase evidence of fileless malware. Always copy logs and artefacts to a secure, write-once location before proceeding.

→ [Eradication and Recovery](eradication-and-recovery.md)

## 5. Contain

Containment stops the bleeding. The correct action depends on incident type:

| Incident type | Containment action |
| :------------ | :----------------- |
| Compromised endpoint | Network isolate (EDR, VLAN change, firewall ACL) |
| Compromised account | Disable account, revoke all sessions and tokens |
| Ransomware | Isolate affected hosts, preserve encrypted files for decryption |
| Data exfiltration | Block destination IP/domain, capture egress traffic |
| Phishing campaign | Quarantine malicious emails, reset credentials for recipients |

→ [Automated Containment](automated-containment.md) · [Ransomware Host Isolation](ransomware-host-isolation.md)

## 6. Eradicate and recover

Eradication removes all attacker presence: malware, persistence mechanisms, compromised credentials, and any backdoors. Recovery restores normal operations from clean backups or rebuilds, with enhanced monitoring in place.

→ [Eradication and Recovery](eradication-and-recovery.md)

## 7. RACI — who does what

A RACI matrix prevents action gaps and duplicate effort under pressure:

| Action | IR Lead | Analyst | CISO | Legal | Communications |
| :----- | :------ | :------ | :--- | :---- | :------------- |
| Declare incident | R | I | I | I | I |
| Triage and scope | A | R | I | — | — |
| Containment decision | A | R | C | C | — |
| Regulatory notification | I | — | A | R | C |
| External communication | C | — | A | C | R |
| Post-incident report | C | R | A | I | — |

*R = Responsible · A = Accountable · C = Consulted · I = Informed*

## 8. Hybrid cloud — platform-specific runbook additions

Hybrid environments require runbook sections for each platform where the incident may touch infrastructure:

```powershell
# Azure — revoke all sessions for a compromised account
Revoke-AzureADUserAllRefreshToken -ObjectId (Get-AzureADUser -SearchString "compromised@example.com").ObjectId

# Azure — disable an account immediately
Set-AzureADUser -ObjectId "<guid>" -AccountEnabled $false
```

```bash
# AWS — disable compromised IAM user access key
aws iam update-access-key \
  --access-key-id <AKIAIOSFODNN7EXAMPLE> \
  --status Inactive \
  --user-name compromised-user
```

→ [Azure Resource Hijacking Response](azure-resource-hijacking.md) · [Compromised Service Principal](compromised-service-principal.md)

## Related

- [Eradication and Recovery](eradication-and-recovery.md)
- [Automated Containment](automated-containment.md)
- [Post-Incident Lessons Learned](post-incident-lessons-learned.md)
- [Actions on Objectives — Reporting](../../offensive/actions-on-objectives-reporting.md)

## External Resources & White Papers

- [NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CISA Incident Response Playbooks](https://www.cisa.gov/resources-tools/resources/federal-government-cybersecurity-incident-and-vulnerability-response-playbooks)

## Citations

- Rael, J. & Meijer, A. *Security Architecture for Hybrid Cloud*. O'Reilly, 2024 — pp. 357–358 (security operations chapter artifacts), pp. 362–372 (runbook techniques, RACI, swimlane procedures).
