---
title: Social Engineering (Phishing, Vishing, Pretexting, Tailgating)
type: concept
platforms: [Microsoft 365, Exchange Online, Microsoft Defender]
languages: [KQL, PowerShell]
tasks: [Incident Response, Investigation, Hardening]
category: Human Attacks
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, social-engineering, phishing, awareness]
aliases: [Social Engineering Techniques, Spear Phishing, Smishing (SMS Phishing), Vishing (Voice Phishing), Caller ID Spoofing, Pretexting, Baiting, Quid Pro Quo, Tailgating, Diversion Theft, "Rachel Tobac's Social Engineering Best Practices", How to Simulate Social Engineering Attacks, How to Run a Phishing Simulation Campaign, How to Create a Security Awareness Training Program, Awareness and Training]
difficulty: basic
verified: false
---

# Social Engineering (Phishing, Vishing, Pretexting, Tailgating)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** social engineering manipulates people into handing over access, money or information, so the defence is process and verification as much as technology.

## What it is

| Technique | How it works |
| :--- | :--- |
| **Phishing / spear phishing** | mass or tailored email with a malicious link or attachment; spear phishing uses research ([OSINT](osint.md)) on one target |
| **Smishing** | the same over SMS / messaging apps (parcel, bank, MFA reset lures) |
| **Vishing** | phone calls, often with **caller ID spoofing** — e.g. "IT helpdesk" asking for an MFA code |
| **Pretexting** | an invented scenario and role (auditor, new employee, vendor) to justify the request |
| **Baiting** | infected USB sticks or "free download" lures |
| **Quid pro quo** | a service in exchange for access — "I'll fix your laptop, just install this tool" |
| **Tailgating / piggybacking** | following someone through a secured door |
| **Diversion theft** | redirecting a delivery or payment to the attacker (overlaps business email compromise) |

Attackers exploit authority, urgency, fear, helpfulness and familiarity. Helpdesk password and MFA resets are a top
target (MGM Resorts, 2023).

## How it works

1. **Research** the target with OSINT (org chart, vendors, tone of internal email).
2. **Make contact** through the channel least protected by technology — phone and personal messaging.
3. **Create pressure** so the victim skips verification.
4. **Cash out:** credentials, MFA approval, remote-access tool install, payment change.

Defences that work: phishing-resistant MFA, verified call-back procedures for resets and payment changes, external
email tagging, attachment sandboxing, and **regular simulations plus short training** that teach reporting, not shame.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1566](https://attack.mitre.org/techniques/T1566/) Phishing (incl. .004 Spearphishing Voice) · [T1598](https://attack.mitre.org/techniques/T1598/) Phishing for Information · [T1684.001](https://attack.mitre.org/techniques/T1684/001/) Social Engineering: Impersonation (formerly T1656) |
| **What it leads to** | initial access in most breaches, business email compromise, MFA bypass via helpdesk |
| **Where defenders meet it** | reported phish mailbox, helpdesk tickets, payment-change requests |

## Do it

Running a phishing simulation: get written approval, exclude no one by default, pick realistic lures, measure
**report rate and time-to-report** (not just click rate), and follow every click with a 2-minute lesson.

```kql
// Users who clicked a URL in an email later flagged as phishing
UrlClickEvents
| where TimeGenerated > ago(7d) and ActionType == "ClickAllowed"
| join kind=inner (EmailEvents | where ThreatTypes has "Phish" | project NetworkMessageId, Subject, SenderFromAddress) on NetworkMessageId
| project TimeGenerated, AccountUpn, Url, Subject, SenderFromAddress
```

```powershell
# Search a mailbox audit for inbox rules created after a suspected phish (Exchange Online)
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -Operations New-InboxRule, Set-InboxRule -ResultSize 100
```

## See it

| Source | What you see |
| :--- | :--- |
| Defender for Office `EmailEvents` / `UrlClickEvents` | delivery verdict, threat type, who clicked |
| Entra `SigninLogs` | sign-in from new IP / ASN right after the click; MFA method changed after a "helpdesk" call |
| Helpdesk tickets | reset requests that bypassed call-back verification |

## Detect it

- Respond: [Phishing email triage](../../tasks/incident-response/phishing-email-triage.md) · [Account compromise](../../tasks/incident-response/account-compromise.md)
- Investigate: [M365 audit log investigation](../../platforms/microsoft-365/audit-log-investigation.md)
- Harden: [Authentication, MFA and SSO](authentication-mfa-sso.md) — phishing-resistant methods

## Related concepts

- [OSINT and Reconnaissance](osint.md) · [Authentication, MFA and SSO](authentication-mfa-sso.md) · [Man-in-the-Middle Attacks](man-in-the-middle.md)
