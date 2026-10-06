---
title: Investigation Playbook — Phishing Email Triage
type: workflow
platforms:
  - Microsoft 365
  - Exchange Online
languages:
  - PowerShell
  - KQL
tasks:
  - Incident Response
  - Investigation
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - playbook
  - phishing
  - exchange
  - email-triage
---

# Investigation Playbook — Phishing Email Triage

Systematic protocol to analyze malicious email deliveries, credential harvesting pages, macro attachments, and tenant-wide recipient exposure.

---

## 1. Objective & Scope

- **What is being investigated**: User-reported or automated gateway-flagged email containing malicious payloads, fake login links, or invoice fraud.
- **MITRE ATT&CK Mapping**: [T1566 - Phishing](https://attack.mitre.org/techniques/T1566/).

---

## 2. Telemetry Queries

### Microsoft Defender XDR — Tenant Recipient Blast Radius

```kql
EmailEvents
| where SenderFromAddress =~ "suspicious-sender@domain.com" or Subject has "Urgent Invoice Payment"
| project Timestamp, NetworkMessageId, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
| summarize RecipientCount = count(), Recipients = make_set(RecipientEmailAddress) by NetworkMessageId, Subject
```

### URL Click Assessment

```kql
UrlClickEvents
| where Url has "login-verify-account" or Url has "secure-doc-share"
| project Timestamp, AccountUpn, IPAddress, Url, ActionType
```

---

## 3. Containment & Tenant Purging

```powershell
# Soft-delete the phishing email across all user mailboxes in Exchange Online
# Prerequisites: Compliance Administrator or eDiscovery Manager role
New-ComplianceSearch -Name "Purge-Phish-20261006" -ExchangeLocation All -ContentMatchQuery 'Subject:"Urgent Invoice Payment" AND From:"suspicious-sender@domain.com"'
Start-ComplianceSearch -Name "Purge-Phish-20261006"

# Verify search completion, then purge
New-ComplianceSearchAction -SearchName "Purge-Phish-20261006" -Purge -PurgeType SoftDelete
```
