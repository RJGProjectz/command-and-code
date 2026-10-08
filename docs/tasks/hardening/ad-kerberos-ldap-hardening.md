---
title: Hardening — Active Directory Kerberos & LDAP Protocol Hardening
type: workflow
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
tasks:
  - Hardening
  - Administration
  - Assurance
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - active-directory
  - kerberos
  - ldap
  - gmsa
  - kerberoasting
  - channel-binding
  - hardening
---

# Hardening — Active Directory Kerberos & LDAP Protocol Hardening

Production runbook for eliminating Kerberoasting and NTLM coercion/relay attacks by deploying Group Managed Service Accounts (gMSA), mandating LDAP Channel Binding and Signing, deprecating RC4 encryption, and implementing the Protected Users security group.

---

## 1. Threat Model & Protocol Exposure

Default Active Directory configurations expose legacy protocol concessions that adversaries exploit for credential theft and domain escalation:

- **Kerberoasting ([T1558.003](https://attack.mitre.org/techniques/T1558/003/))**: Any domain user can request a Kerberos Ticket Granting Service (TGS) ticket for any Service Principal Name (SPN) registered to a standard user account. The ticket is encrypted with the service account's password hash and cracked offline.
- **LDAP Relay & Coercion ([T1187](https://attack.mitre.org/techniques/T1187/))**: Coerced authentication protocols (e.g., PetitPotam, PrinterBug) force Domain Controllers to authenticate to attacker listeners via NTLM. The attacker relays this authentication into unauthenticated, unsigned LDAP (port 389) or Active Directory Certificate Services (AD CS) to compromise the entire domain.
- **Kerberos RC4 Downgrade**: Legacy `RC4_HMAC_MD5` (`0x4`) ticket encryption uses obsolete cryptographic hashing easily brute-forced with modern GPU rigs.

---

## 2. Step 1: Deploy Group Managed Service Accounts (gMSA)

Group Managed Service Accounts (gMSAs) eliminate Kerberoasting by replacing standard user accounts with KDC-managed identities whose 120-character passwords rotate automatically every 30 days.

### Create Key Distribution Services (KDS) Root Key
The KDS Root Key must exist in Active Directory before any domain controller can generate gMSA passwords:

```powershell
# Create KDS Root Key (effective immediately; requires Active Directory PowerShell module)
Add-KdsRootKey -EffectiveImmediately
```

### Provision gMSA for Services (IIS, SQL, Scheduled Tasks)
```powershell
# 1. Create target security group containing servers permitted to use this account
New-ADGroup -Name "<SECURITY_GROUP>" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=<DOMAIN>,DC=LOCAL"

# 2. Provision new gMSA restricted to that server group
New-ADServiceAccount -Name "<GMSA_NAME>" `
    -DNSHostName "<GMSA_NAME>.<DOMAIN>.LOCAL" `
    -PrincipalsAllowedToRetrieveManagedPassword "<SECURITY_GROUP>" `
    -KerberosEncryptionType AES128, AES256

# 3. Associate Service Principal Name (SPN) if hosting network services
Set-ADServiceAccount -Identity "<GMSA_NAME>" -Add @{ServicePrincipalNames = "HTTP/<HOST>.<DOMAIN>.LOCAL"}
```

### Install & Test gMSA on Host Server
Run this on the host server running the service:

```powershell
# Install gMSA onto local computer
Install-ADServiceAccount -Identity "<GMSA_NAME>"

# Test whether local machine can retrieve password from KDC
Test-ADServiceAccount -Identity "<GMSA_NAME>"
# Expected return value: True
```

---

## 3. Step 2: Enforce LDAP Signing & Channel Binding Tokens

Enforcing LDAP Signing and Channel Binding Tokens (CBT) blocks NTLM relay attacks against Domain Controllers by binding the TLS session to the authentication payload.

### Registry Configuration (Domain Controllers)
```powershell
# 1. Enforce LDAP Server Signing (Requires signing: 2)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2 -Type DWord

# 2. Enforce LDAP Channel Binding Tokens (Always enforce: 2)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
```

### Group Policy Deployment
Configure in Default Domain Controllers Policy:
- `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options`:
    - **Domain controller: LDAP server signing requirements**: Set to **Require signing**.
    - **Domain controller: LDAP server channel binding token requirements**: Set to **Always**.

### Audit Unsigned LDAP Connections (Pre-Enforcement)
Before enforcing signing, audit Directory Service Event Log Event ID **2889** to identify legacy applications performing simple/unsigned binds:

```powershell
# Query last 100 unsigned LDAP bind attempts on Domain Controller
Get-WinEvent -FilterHashtable @{
    LogName = "Directory Service"
    Id      = 2889
} -MaxEvents 100 -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        ClientIP    = $_.Properties[0].Value
        Account     = $_.Properties[1].Value
        BindingType = $_.Properties[2].Value
    }
} | Format-Table -AutoSize
```

---

## 4. Step 3: Deprecate RC4 & Enforce AES-Only Kerberos

Eliminate `RC4_HMAC_MD5` across Kerberos ticket exchanges, enforcing `AES128-CTS-HMAC-SHA1-96` (`0x8`) and `AES256-CTS-HMAC-SHA1-96` (`0x10`).

### Audit Existing Accounts with SPNs
```powershell
# Audit all user accounts with SPNs that still permit RC4
Get-ADUser -Filter {ServicePrincipalNames -like "*"} -Properties ServicePrincipalNames, msDS-SupportedEncryptionTypes |
    Select-Object Name, msDS-SupportedEncryptionTypes, @{N='Encryption';E={
        switch ($_.('msDS-SupportedEncryptionTypes')) {
            0  { "Default (RC4 Allowed)" }
            4  { "RC4 Only" }
            16 { "AES256 Only" }
            24 { "AES128 & AES256" }
            default { $_.('msDS-SupportedEncryptionTypes') }
        }
    }} | Format-Table -AutoSize
```

### Configure Accounts to Require AES Encryption
```powershell
# Set msDS-SupportedEncryptionTypes to 0x18 (24 decimal = AES128 + AES256)
Get-ADUser -Filter {ServicePrincipalNames -like "*"} | ForEach-Object {
    Set-ADUser -Identity $_ -Replace @{'msDS-SupportedEncryptionTypes' = 24}
}
```

---

## 5. Step 4: Deploy the Protected Users Security Group

Active Directory includes the built-in **Protected Users** security group (introduced in Windows Server 2012 R2). Adding tier-0 and tier-1 administrative accounts to this group automatically triggers non-configurable protocol restrictions:

- **Blocks NTLM Authentication**: Authentication attempts using NTLM are actively rejected.
- **Enforces AES Kerberos**: DES and RC4 encryption types are disabled.
- **Suppresses Credential Caching**: Plaintext credentials are never cached in LSASS (protects against Mimikatz memory scraping).
- **Caps TGT Lifetime**: Ticket Granting Ticket (TGT) lifetimes are capped at 4 hours and cannot be renewed.
- **Blocks Delegation**: Accounts cannot be delegated (constrained or unconstrained).

### Add Tier-0 Administrators to Protected Users
```powershell
# Add privileged administrative accounts to Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "<ADMIN_USER>"

# Verify membership
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName
```

---

## 6. Verification & Telemetry Validation

### Verify Kerberos Ticket Encryption (Event ID 4769)
Ensure Kerberos TGS requests negotiate `0x12` (AES-256):

```powershell
# Query Security Event Log on Domain Controller for Kerberos TGS requests
Get-WinEvent -FilterHashtable @{
    LogName = "Security"
    Id      = 4769
} -MaxEvents 20 | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        ServiceName    = $_.Properties[1].Value
        ClientAddress  = $_.Properties[3].Value
        TicketOptions  = $_.Properties[4].Value
        EncryptionType = $_.Properties[5].Value # 0x12 = AES256, 0x17 = RC4 (Dangerous)
    }
} | Format-Table -AutoSize
```

---

## Related Guides

- [Fundamentals — Kerberos Protocol Mechanics](../../fundamentals/kerberos.md)
- [Fundamentals — LDAP Protocol Architecture](../../fundamentals/identity/ldap.md)
- [Threat Hunting — Kerberoasting & AS-REP Roasting](../threat-hunting/kerberoasting-asreproast-hunting.md)
- [Active Directory STIG Compliance](../assurance/ad-stig-compliance.md)
- [Active Directory Domain Services Management](../administration/active-directory-domain-management.md)
