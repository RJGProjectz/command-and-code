---
title: Fundamentals — Kerberos Authentication Protocol
type: entry
platforms:
  - Windows
  - Active Directory
languages:
  - PowerShell
tasks:
  - Investigation
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - kerberos
  - active-directory
  - authentication
  - fundamentals
---

# Fundamentals — Kerberos Authentication Protocol

Kerberos v5 is the default authentication mechanism in Active Directory, relying on symmetric cryptography and trusted Key Distribution Centers (KDCs).

## 1. Authentication Exchange Flow

```text
[Client] ──(1) AS-REQ (Timestamp encrypted with User Hash)──► [KDC: Kerberos KDC]
[Client] ◄──(2) AS-REP (TGT + Session Key)─────────────────── [KDC]
[Client] ──(3) TGS-REQ (TGT + Authenticator + SPN)──────────► [KDC]
[Client] ◄──(4) TGS-REP (Service Ticket encrypted with SPN)── [KDC]
[Client] ──(5) AP-REQ (Service Ticket)──────────────────────► [Target Service]
```

---

## 2. Attack Vectors

| Technique | Mechanism | Mitigation |
| :--- | :--- | :--- |
| **Kerberoasting** ([T1558.003](https://attack.mitre.org/techniques/T1558/003/)) | Requesting TGS tickets for accounts with SPNs and cracking offline | Enforce 25+ char passwords or Group Managed Service Accounts (gMSA) |
| **AS-REP Roasting** ([T1558.004](https://attack.mitre.org/techniques/T1558/004/)) | Requesting AS-REP for accounts with `Do not require Kerberos preauthentication` | Ensure pre-authentication is enforced on all accounts |
| **Golden Ticket** ([T1558.001](https://attack.mitre.org/techniques/T1558/001/)) | Forging TGTs using the compromised `krbtgt` password hash | Rotate `krbtgt` password twice in succession |

---

## 3. Operational Inspection

```powershell
# Inspect active Kerberos tickets in current logon session
klist.exe

# Find accounts vulnerable to AS-REP Roasting
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName
```
