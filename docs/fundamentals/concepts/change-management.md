---
title: Change Management
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, Bash]
tasks: [Administration, Assurance, Hardening, Governance]
category: Governance and Law
security_domain: Governance
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, change-management, change-control, itil, governance, compliance, cob, risk-management]
aliases: [change management, change control, change control board, CCB, change advisory board, CAB, ITIL change management, change freeze]
difficulty: basic
verified: false
---

# Change Management
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** a formal process that requires changes to systems, infrastructure, or applications to be reviewed, risk-assessed, and approved before implementation — preventing unauthorised or poorly tested changes from introducing vulnerabilities or outages.

## What it is

Every unplanned or unapproved change to a production environment is a potential security or availability event. A firewall rule added without review might open an unintended attack surface. A patch applied without testing might break a dependent service. Change management addresses this by imposing a structured workflow between "someone wants to make a change" and "the change happens."

In its minimal form, change management has two functions: authorisation (the change has been reviewed and approved by accountable parties) and risk evaluation (potential negative consequences have been weighed, and rollback or mitigation steps exist). Larger organisations add a Change Control Board (CCB) or Change Advisory Board (CAB) — a standing committee that reviews significant changes on a scheduled cycle, ensuring multiple stakeholders sign off before changes reach production.

Change management is not bureaucracy for its own sake. Several regulatory and certification frameworks require a documented change process: SOC 2, ISO/IEC 27001, and PCI DSS all mandate evidence that changes go through a controlled process. Cloud environments modify the calculus somewhat — continuous delivery pipelines and feature flags make very small, automatically tested changes lower risk than the equivalent change on a monolithic on-premises system — but the principle of authorisation and rollback planning remains.

## How it works

A typical change lifecycle:

```text
Request for change (RFC)
        │
        ▼
Classification: standard / normal / emergency
        │
        ├─ Standard ──► pre-approved, low-risk, follow a template → implement
        │
        ├─ Normal ───► review by CCB/CAB; impact, risk, rollback assessed → approve / reject
        │
        └─ Emergency ─► expedited approval with post-change review; highest scrutiny
                │
                ▼
Implementation in a maintenance window
        │
        ▼
Post-implementation review: did the change work? were there side effects?
        │
        ▼
Closed: documented in the change management system
```

Modern DevOps pipelines often implement change management implicitly through pull-request reviews, automated test gates, and deployment approvals — the same controls as a CCB, compressed into a CI/CD workflow with an audit trail in the version control system.

## Why it matters

| | |
| :--- | :--- |
| **Framework reference** | ITIL 4 Change Enablement practice · ISO/IEC 27001:2022 Annex A 8.32 (Change management) |
| **What poor change management leads to** | Unauthorised configuration changes that open attack surfaces; patching backlogs because approval processes are too slow; audit findings that block certification |
| **Where security teams meet it** | Firewall rule reviews; server decommission approvals; emergency patch deployment; cloud resource configuration changes flagged by CSPM tools |

## Do it

```bash
cc find "change control"
cc view docs/fundamentals/concepts/risk-management-governance.md
cc view docs/tasks/assurance/index.md
```

Audit recent configuration changes on a Windows host you own:

```powershell
# List recent changes to firewall rules (requires admin rights, on a machine you own)
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' } |
  Sort-Object -Property DisplayName |
  Select-Object DisplayName, Direction, Action, Profile | Format-Table -AutoSize
```

```bash
# On Linux: review recent changes to system configuration files
# Check /etc/sudoers changes in the past 7 days on a machine you own
find /etc -name '*.conf' -newer /etc/hostname -mtime -7 2>/dev/null | head -20
```

!!! caution "SAFETY WARNING: VALIDATE BEFORE EXECUTION"
    The commands above audit configuration state on machines you own. Any changes identified should go through your organisation's change management process before remediation. Do not modify production configurations without appropriate authorisation.

## See it

Change management failures appear in audit logs, incident postmortems, and compliance findings:

| Source | What you see |
| :--- | :--- |
| Cloud CSPM (Defender for Cloud, AWS Security Hub) | Infrastructure change detected outside a change window, or by an identity not associated with change requests |
| Windows Security log | Event ID 4719 (System audit policy changed), 4739 (Domain policy changed), 4902 (Per-user audit policy table created) |
| Azure Activity Log / AWS CloudTrail | Resource modification events where the calling identity is not the expected service account or pipeline |
| Ticketing system | Changes implemented with no corresponding approved RFC; emergency changes with no post-implementation review |
| Compliance audit | Missing documentation for a configuration change; change log entries that cannot be traced to an approved request |

## Detect it

- Detection: [Detection Engineering](../../tasks/detection-engineering/index.md)
- Assurance: [Assurance and Compliance Tasks](../../tasks/assurance/index.md)
- Govern: [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- Harden: [Hardening Tasks](../../tasks/hardening/index.md)

## Security controls and integration

| Control | Why it helps |
| :--- | :--- |
| Change window enforcement | Restricts when changes can be made, limiting the blast radius of an unauthorised midnight change |
| Mandatory rollback plan | Every approved change includes documented steps to revert — reduces Mean Time to Recovery (MTTR) |
| Security review gate | A security practitioner reviews the RFC before approval, catching misconfigurations before they reach production |
| Automated drift detection (CSPM / IaC) | Detects configuration that diverges from an approved baseline — essentially an always-on change audit |
| Separation of duties | The person who requests a change cannot also be the person who approves and implements it |
| Immutable infrastructure / GitOps | Infrastructure state is defined in version control; any drift is an unauthorised change, automatically detectable |

## Related concepts

- [Risk Management, Policies and Compliance Audits](risk-management-governance.md)
- [Secure SDLC, DevSecOps and Secure Coding](secure-sdlc-devsecops.md)
- [Vulnerability Management](vulnerability-management.md)
