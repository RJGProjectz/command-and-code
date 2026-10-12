---
title: Password Attacks and Defences (Spraying, Cracking, Wordlists)
type: concept
platforms: [Windows, Entra ID, Microsoft Defender]
languages: [PowerShell, KQL]
tasks: [Threat Hunting, Hardening, Incident Response]
category: Identity Attacks
security_domain: Identity
author: RJGProjectz
date_created: 2026-10-12
last_updated: 2026-10-12
tags: [concept, passwords, password-spraying, cracking, wordlists]
aliases: [How to use Password Cracking Techniques, "Generating a Wordlist & Cracking the Password", wordlists for password cracking, John the Ripper, Crunch]
difficulty: intermediate
verified: false
---

# Password Attacks and Defences (Spraying, Cracking, Wordlists)
> **Created**: 2026-10-12T04:00:00Z
> **Last Modified**: 2026-10-12T04:00:00Z
> **Author**: RJGProjectz

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Remove this block when `verified: true`.
**In one line:** attackers guess passwords online against login pages or offline against stolen hashes, so defence combines unguessable passwords, slow hashes, MFA and detection of guessing patterns.

## What it is

| Attack | Where | Signal |
| :--- | :--- | :--- |
| Brute force | one account, many passwords, online | many failures for one user → lockout |
| **Password spraying** | many accounts, a few common passwords | failures across many users from one source |
| Credential stuffing | username/password pairs from other breaches | logins succeed with valid creds from new IPs |
| **Offline cracking** | stolen hashes (NTDS.dit, SAM, Kerberos tickets, Wi-Fi handshakes, web DB dumps) | none — invisible to the victim |

Offline crackers such as John the Ripper and Hashcat test **wordlists** (leaked-password lists, company-specific words),
**rules** (Summer2026!, P@ssw0rd), **masks** and generated lists (Crunch builds every combination of a pattern).
Fast hashes (NTLM, MD5) fall at billions of guesses per second; slow ones (bcrypt, Argon2) at thousands.

## How it works

Defences by stage:

1. **Make guessing pointless:** long passphrases (NIST SP 800-63B), block common and breached passwords (Entra Password
   Protection, custom banned lists), no forced periodic rotation.
2. **Stop online guessing:** MFA, smart lockout, block legacy authentication, rate limits.
3. **Make offline cracking slow:** salted slow hashes in your apps ([hash functions](hash-functions.md)); AES-only
   Kerberos and long service-account passwords ([Kerberoasting](kerberoasting.md)); LAPS for local admin.
4. **Audit:** with authorisation, test your own AD password hashes against breached-password lists to find weak ones.

## Why it matters

| | |
| :--- | :--- |
| **MITRE ATT&CK** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Guessing · [T1110.002](https://attack.mitre.org/techniques/T1110/002/) Cracking · [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Spraying · [T1110.004](https://attack.mitre.org/techniques/T1110/004/) Credential Stuffing |
| **What it leads to** | initial access with valid accounts, domain compromise from one cracked service account |
| **Where defenders meet it** | lockout storms, Entra risky sign-ins, failed-logon spikes on VPN and OWA |

## Do it

```kql
// Password spraying against Entra ID: one IP, many users, wrong password (50126)
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "50126"
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress
| where Users > 10
| order by Users desc
```

```powershell
# On-prem spraying: failed logons per source across many accounts (DC security log)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddHours(-1) } |
    ForEach-Object -Process { $xml = [xml]$_.ToXml(); [pscustomobject]@{
        User = ($xml.Event.EventData.Data | Where-Object -Property Name -EQ -Value 'TargetUserName').'#text'
        Ip   = ($xml.Event.EventData.Data | Where-Object -Property Name -EQ -Value 'IpAddress').'#text' } } |
    Group-Object -Property Ip | Where-Object -Property Count -GT -Value 20 |
    Select-Object -Property Name, Count
```

## See it

| Source | What you see |
| :--- | :--- |
| Security 4625 / 4771 (0x18) | failed NTLM / Kerberos pre-auth logons — many users per source = spraying |
| Entra `SigninLogs` | `50126` invalid password, `50053` locked out, sign-ins from known spray infrastructure |
| Security 4740 | account lockouts |

## Detect it

- Investigate: [Failed authentication](../../tasks/investigation/failed-authentication.md) · [Account lockout troubleshooting](../../tasks/troubleshooting/account-lockout-troubleshooting.md)
- Hunt: [Kerberoasting and AS-REP roasting](../../tasks/threat-hunting/kerberoasting-asreproast-hunting.md)
- Harden: [Authentication, MFA and SSO](authentication-mfa-sso.md)

## Related concepts

- [Hash Functions](hash-functions.md) · [Credential Dumping](credential-dumping.md) · [WPA Passphrase Attacks](wifi-passphrase-attacks.md) · [Cryptographic Attacks](cryptographic-attacks.md)
