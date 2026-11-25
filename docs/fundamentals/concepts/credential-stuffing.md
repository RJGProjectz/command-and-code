---
title: Credential Stuffing
type: concept
platforms: [Windows, Linux, Azure, AWS]
languages: [PowerShell, Bash, Python]
tasks: [Incident Response, Hardening, Detection Engineering, Threat Hunting]
category: Identity Attacks
security_domain: Identity
author: RJGProjectz
date_created: 2026-11-24
last_updated: 2026-11-24
tags: [concept, credential-stuffing, account-takeover, authentication, brute-force, identity-attacks]
aliases: [credential stuffing attack, ATO, account takeover, stuffing attack, combo list attack]
difficulty: intermediate
verified: false
---

# Credential Stuffing
> **Created**: 2026-11-24T00:00:00Z
> **Last Modified**: 2026-11-24T00:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.

**In one line:** an automated attack that replays username-password pairs from leaked databases against login endpoints, exploiting the widespread habit of reusing passwords across services.

## What it is

Credential stuffing is distinct from brute-force attacks: rather than generating or guessing passwords at random, an attacker starts with a known-good credential pair — typically from a data breach dump — and simply tries it against a different target. The assumption is that many users reuse the same email address and password combination across dozens of sites. When one site suffers a breach, every other site where that user registered with the same password becomes vulnerable.

Modern stuffing operations are highly automated. Attackers purchase or download "combo lists" — structured text files pairing email addresses with their corresponding plaintext or cracked passwords — and feed them into tools that submit login requests at scale. Because the credentials are real, the attack bypasses password-complexity checks and length requirements entirely. A single successful match yields a valid authenticated session for further exploitation.

The economic impact is substantial. Research published by the Ponemon Institute found that stuffing attacks cost affected organizations millions annually in customer support, fraud remediation, and reputational damage. For applications handling financial, healthcare, or personal data, even a small authentication success rate across a large combo list can expose thousands of accounts.

## How it works

```text
Data breach at Site A
        │
        ▼
Combo list: user@email.com : Password123
        │
        ▼
Automated tool iterates list → POST /login to Site B, Site C, Site D
        │
        ├── 403 / 401 ──► skip (invalid or rate-limited)
        └── 200 / redirect ──► valid session captured
                 │
                 ▼
           Account takeover: exfiltrate data, pivot, sell access
```

A typical attack sequence:

1. **Obtain combo list** — purchase from underground markets, harvest from public paste sites, or run cracking tools against a leaked hash dump.
2. **Configure tooling** — set up a rotating proxy pool to distribute requests across IP ranges; configure per-IP request rates to stay below threshold detectors.
3. **Target discovery** — identify login endpoints via passive recon (`/login`, `/api/auth`, OAuth flows) and map any visible rate-limit or CAPTCHA behavior.
4. **Execute stuffing run** — submit credential pairs in batches; record HTTP status codes, response lengths, and redirect targets to separate successes from failures.
5. **Validate hits** — verify captured sessions (account balance, stored payment methods, PII) to triage value before selling or exploiting.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) — Credential Stuffing |
| **What it leads to** | account takeover; fraud; lateral movement if the account has cloud console or VPN access |
| **Where defenders meet it** | spike in failed logins followed by a success, logins from unusual geographies or ASNs, unusually high authentication API traffic |

## Do it

```bash
cc find "credential stuffing"
cc view docs/fundamentals/concepts/password-attacks.md
cc view docs/tasks/hardening/index.md
```

Inspect authentication log volume for anomalies on a system you own:

```powershell
# Windows: count failed logon events (4625) in the last hour
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4625
    StartTime = (Get-Date).AddHours(-1)
} | Group-Object -Property { $_.Properties[5].Value } |
    Sort-Object Count -Descending | Select-Object -First 20
```

```bash
# Linux: count unique source IPs in auth.log in the last 100 lines
grep "Failed password" /var/log/auth.log | tail -100 | \
  awk '{print $NF}' | sort | uniq -c | sort -rn
```

!!! caution "SAFETY WARNING: VALIDATE BEFORE EXECUTION"
    The commands above read local logs on a host you own for defensive analysis. Do not run credential-testing tooling against systems you do not own or have explicit written authorisation to test.

## See it

Credential stuffing leaves a characteristic two-phase signature: a large volume of authentication failures followed by a small cluster of unexpected successes — unlike pure brute force, which shows only failures before finally succeeding against a weak password.

| Source | What you see |
| :--- | :--- |
| Application / WAF logs | High volume of POST requests to `/login` from many IPs; short, uniform request intervals |
| Azure AD / Entra ID Sign-in logs | Many `50126` (bad password) failures across many user accounts in a narrow time window; successful sign-in from an unusual IP immediately after |
| Windows Security log | Event ID 4625 (failed logon, type 3) spike across multiple accounts from one source |
| Rate-limit or WAF telemetry | Requests distributed across many ASNs or Tor exit nodes to bypass per-IP throttling |
| Successful sign-in anomaly | Valid logon from a country, ISP, or device the account has never used; session created immediately after a failed-login burst |

## Detect it

- Detection: [Credential Access Detection](../../detection/index.md)
- Hunt: [Threat Hunting — Authentication Anomalies](../../tasks/threat-hunting/index.md)
- Respond: [Incident Response](../../tasks/incident-response/index.md)
- Harden: [Authentication and MFA hardening](../../fundamentals/concepts/authentication-mfa-sso.md)

## Hardening controls

| Control | Why it helps |
| :--- | :--- |
| Multi-factor authentication | Stolen credentials alone are insufficient — attacker also needs the second factor |
| Breached-password check on login | Reject credentials that appear in known breach lists (e.g. Have I Been Pwned API, Azure AD password protection) |
| Rate limiting and account lockout | Slow or block automated submission; balance against DoS risk |
| Bot-detection and CAPTCHA | Add friction that defeats simple HTTP clients without slowing real users much |
| Anomalous-login alerting | Trigger on impossible travel, new device, or login-after-failure-spike |
| IP reputation filtering | Block or challenge requests from known proxy/VPN/Tor exit nodes at the WAF layer |

## Related concepts

- [Password Attacks and Defences](password-attacks.md)
- [Authentication, MFA and SSO](authentication-mfa-sso.md)
- [Identity and Access Management](identity-access-management.md)
- [Threat Intelligence and the Cyber Kill Chain](threat-intelligence-kill-chain.md)
