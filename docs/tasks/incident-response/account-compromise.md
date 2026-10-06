---
title: Account Compromise Investigation
type: workflow
platforms: [Entra ID, Exchange Online, Microsoft 365, Windows]
languages: [PowerShell, KQL]
tasks: [Incident Response, Investigation]
category: Workflow
tags: [workflow, account compromise, bec, entra id, mfa, inbox rules, session revocation]
aliases: [compromised account, account takeover, bec investigation, impossible travel, user compromised what to do]
difficulty: intermediate
verified: true
last_verified: 2026-10-05
search:
  boost: 3
---

# Account Compromise Investigation

**Trigger:** risky sign-in alert, impossible travel, user reports MFA prompts they did not request, suspicious inbox rule, or phishing click with credential entry.

## 1. Identify the account and its privilege

Is it privileged (admin roles, access to finance, VIP)? Hybrid (synced from AD) or cloud-only?

→ [Entra: look up a user](../../platforms/microsoft-365/entra.md#look-up-a-user) · [Privileged role members](../../platforms/microsoft-365/entra.md#privileged-role-members)

## 2. Review authentication history

Sign-ins over the last 14–30 days: successes from new IPs, countries, devices, user agents; legacy protocols; MFA results.

→ [KQL: one user's sign-in history](../../detection/kql/logon-identity.md#one-users-sign-in-history) · [PowerShell sign-in logs](../../platforms/microsoft-365/entra.md#sign-in-logs)

## 3. Review the source IPs

Hosting provider / VPN / anonymiser ASNs, and whether other users signed in from the same IPs.

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where IPAddress in ("<TARGET_IP>")
| summarize Users = make_set(UserPrincipalName), Results = make_set(ResultType) by IPAddress
```

## 4. Review devices and sessions

Unfamiliar devices in sign-in `DeviceDetail`, new device registrations, PRT issuance.

## 5. Check persistence an attacker would add

- New **MFA methods** → [authentication methods](../../platforms/microsoft-365/entra.md#review-authentication-methods)
- **Inbox rules** and **forwarding** → [inbox rules](../../platforms/microsoft-365/exchange.md#inbox-rules-on-a-mailbox), [forwarding](../../platforms/microsoft-365/exchange.md#mailbox-level-forwarding)
- **Mailbox delegation** → [mailbox permissions](../../platforms/microsoft-365/exchange.md#mailbox-permissions)
- **OAuth consent** to unfamiliar apps → [consent grants](../../platforms/microsoft-365/entra.md#application-consent-grants)
- **Role assignments / app credentials** → [directory changes](../../detection/kql/logon-identity.md#entra-id-directory-changes)

## 6. Review what the attacker did

- Mail sent (internal phishing) → [message trace](../../platforms/microsoft-365/exchange.md#message-trace)
- Mail accessed, files downloaded → unified audit log → [Search-UnifiedAuditLog](../../platforms/microsoft-365/exchange.md#unified-audit-log)
- On-prem logons with the same account → [Windows logon events](../../platforms/windows/event-logs.md#extract-event-fields)

## 7. Contain

Order matters — do these together, quickly:

1. **Disable** the account (cloud and on-prem for hybrid)
2. **Revoke sessions** → [Contain a compromised account](../../platforms/microsoft-365/entra.md#contain-a-compromised-account)
3. **Reset the password** (twice for on-prem accounts if Kerberos ticket abuse is suspected)
4. **Remove attacker MFA methods**, rules, forwarding, consents, delegations
5. **Block** attacker IPs in Conditional Access named locations if they are not shared infrastructure

## 8. Recover and harden

Re-enable with phishing-resistant MFA, review Conditional Access coverage for the gap that was exploited, notify affected recipients if internal phishing occurred.

## Related

- [Failed Authentication](../investigation/failed-authentication.md)
- [Conditional Access](../../platforms/microsoft-365/conditional-access.md)
- [Windows users and groups](../../platforms/windows/users-groups.md)
