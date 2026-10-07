---
title: Hunting Kerberoasting and AS-REP Roasting in Active Directory
type: workflow
platforms:
  - Active Directory
  - Windows
  - Windows Server
  - Splunk
  - Microsoft Defender
languages:
  - PowerShell
  - KQL
  - SPL
tasks:
  - Threat Hunting
  - Investigation
  - Incident Response
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - active-directory
  - kerberos
  - kerberoasting
  - asreproast
  - tgs
  - tgt
  - encryption-downgrade
---

# Hunting Kerberoasting and AS-REP Roasting in Active Directory

Kerberoasting and AS-REP Roasting exploit legitimate Kerberos ticket exchange mechanisms to extract offline-crackable password hashes without requiring administrative privileges on domain controllers.

---

## 1. Attack Mechanics & Telemetry Fingerprints

### Kerberoasting ([T1558.003](https://attack.mitre.org/techniques/T1558/003/))
Any authenticated domain user can request a Kerberos Ticket Granting Service ($TGS$) ticket for any service principal name ($SPN$). The ticket is encrypted with the NTLM hash of the service account. The attacker extracts this ticket and cracks it offline.

- **Key Telemetry**: Windows Security Event ID **4769** (`A Kerberos service ticket was requested`).
- **Signature**: Ticket Encryption Type `0x17` (RC4-HMAC) requested for high-privilege service accounts, or a single workstation requesting tickets for dozens of distinct SPNs in minutes.

### AS-REP Roasting ([T1558.004](https://attack.mitre.org/techniques/T1558/004/))
When an Active Directory user account has the flag `Do not require Kerberos preauthentication` (`DONT_REQ_PREAUTH`) enabled, an adversary can request an Authentication Service Response ($AS-REP$) ticket without knowing the password. The domain controller responds with an encrypted ticket encrypted with the user's password hash.

- **Key Telemetry**: Windows Security Event ID **4768** (`A Kerberos authentication ticket (TGT) was requested`) with Pre-Authentication Type `0` (`Logon without pre-authentication`).

---

## 2. Threat Hunting Queries

### Splunk: Kerberoasting Anomaly Detection (Event ID 4769)

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| eval Service_Name=lower(Service_Name)
| search NOT Service_Name IN ("*$", "krbtgt")
| stats dc(Service_Name) as distinct_spns values(Service_Name) as targeted_services count by src_ip, Target_User_Name
| where distinct_spns > 3
| sort - distinct_spns
```

### Splunk: AS-REP Roasting Detection (Event ID 4768)

```spl
index=wineventlog EventCode=4768 Pre_Authentication_Type=0 Result_Code=0x0
| search NOT Target_User_Name="*$"
| stats count values(Client_Address) as src_ips by Target_User_Name
| sort - count
```

### Microsoft Defender XDR (KQL): Kerberoasting Volume Spike

```kql
IdentityLogonEvents
| where ActionType == "KerberosServiceTicketRequest"
| where TicketEncryptionType has "RC4" or TicketEncryptionType == "0x17"
| where not(ServiceName endswith "$") and ServiceName != "krbtgt"
| summarize DistinctServices = dcount(ServiceName), TargetServices = make_set(ServiceName) by AccountName, IPAddress, bin(Timestamp, 10m)
| where DistinctServices >= 3
| order by DistinctServices desc
```

---

## 3. Host and Domain Active Directory Auditing

Audit vulnerable accounts in Active Directory using the native `ActiveDirectory` PowerShell module before adversaries find them.

```powershell
# 1. Audit all accounts vulnerable to AS-REP Roasting (Preauth Disabled)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} -Properties DoesNotRequirePreAuth, Description, MemberOf |
    Select-Object SamAccountName, Description, MemberOf

# 2. Audit all user accounts with registered SPNs (Kerberoasting Targets)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, AdminCount, PasswordLastSet |
    Select-Object SamAccountName, AdminCount, PasswordLastSet, @{N='SPNs';E={$_.ServicePrincipalName -join '; '}}

# 3. Identify High-Privilege Service Accounts (AdminCount = 1)
# These represent tier-0 / tier-1 targets for Kerberoasting
Get-ADUser -Filter {ServicePrincipalName -like "*" -and AdminCount -eq 1} -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName
```

---

## 4. Remediation & Hardening Controls

1. **Enforce AES-128 / AES-256 Encryption**: Restrict Kerberos encryption types to AES (`0x12` and `0x11`) via Group Policy:
   `Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Network security: Configure encryption types allowed for Kerberos`.
2. **Migrate to Group Managed Service Accounts (gMSA)**: gMSAs feature 128-character complex passwords rotated by the domain controller automatically every 30 days, completely mitigating offline cracking attacks.
3. **Audit and Re-enable Pre-Authentication**: Never configure user accounts with `DONT_REQ_PREAUTH`. Set `Set-ADAccountControl -Identity <User> -DoesNotRequirePreAuth $false`.
