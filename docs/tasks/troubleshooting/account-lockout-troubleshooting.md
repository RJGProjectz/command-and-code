---
title: Active Directory Account Lockout & Bad Password Troubleshooting
type: workflow
platforms: [Windows, Windows Server, Active Directory]
languages: [PowerShell, CMD, Windows CLI]
tasks: [Troubleshooting, Administration]
category: Workflow
tags: [workflow, troubleshooting, lockout, badpwdcount, event-4740, kerberos, ntlm, active-directory]
aliases: [account locked out, find lockout source, who locked out my account, event 4740 caller computer, bad password loop]
difficulty: intermediate
verified: true
last_verified: 2026-10-08
---

# Active Directory Account Lockout & Bad Password Troubleshooting

**Symptom:** a domain user account repeatedly locks out moments after being unlocked, or users report constant password prompt storms despite knowing their current credentials.

---

## 1. Interactive Diagnostic Decision Tree

<div class="cc-tree" data-title="Account Lockout Root Cause Triage" markdown>

<div class="cc-node cc-node--root" data-id="step-pdc-event" markdown>

#### Step 1: Authoritative PDC Emulator Event 4740 Query

In an Active Directory domain, all account lockouts are processed by and centrally logged to the **Primary Domain Controller (PDC) Emulator** FSMO role holder as **Event ID 4740**.

Query the PDC Emulator for recent lockout events for the targeted username:

```powershell
# 1. Discover the domain's authoritative PDC Emulator
$PDC = (Get-ADDomainController -Discover -Service PrimaryDC).HostName

# 2. Extract Event 4740 records with Caller Computer Name
Get-WinEvent -ComputerName $PDC -FilterHashtable @{
    LogName = 'Security'
    Id      = 4740
} -MaxEvents 20 | Where-Object { $_.Properties[0].Value -eq '<USERNAME>' } | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated    = $_.TimeCreated
        TargetUser     = $_.Properties[0].Value
        CallerComputer = $_.Properties[1].Value
        PDC            = $PDC
    }
} | Format-Table -AutoSize
```

**Did Event 4740 return a specific `CallerComputer` hostname?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-workstation-audit">✓ Caller Computer Identified (Workstation / Server)</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-blank-caller">✗ Caller Computer Blank or Points to DC / Radius</button>
</div>

</div>

<div class="cc-node" data-id="step-blank-caller" markdown>

#### Diagnostic Branch: RADIUS, Exchange ActiveSync, or NTLM Proxy

When `CallerComputer` is blank or names an infrastructure server (Exchange, NPS, ADFS, or Domain Controller), the bad authentication is proxied:

1. **Check Kerberos Pre-Authentication Failures (Event ID 4771):**
   ```powershell
   Get-WinEvent -ComputerName $PDC -FilterHashtable @{
       LogName = 'Security'; Id = 4771
   } -MaxEvents 50 | Where-Object { $_.Properties[0].Value -eq '<USERNAME>' } | ForEach-Object {
       [PSCustomObject]@{
           TimeCreated = $_.TimeCreated
           User        = $_.Properties[0].Value
           ClientIP    = $_.Properties[6].Value
           FailureCode = $_.Properties[4].Value # 0x18 = Bad Password
       }
   } | Format-Table -AutoSize
   ```
2. **Check Exchange ActiveSync (EAS) / Mobile Device Loops:**
   Inspect Exchange CAS IIS W3C logs for HTTP 401/403 status codes from mobile devices sending stale ActiveSync tokens:
   ```powershell
   # Search IIS logs on Exchange CAS for the user's mobile device sync attempts
   Get-ChildItem -Path "C:\inetpub\logs\LogFiles\W3SVC*\*.log" | Select-String -Pattern "<USERNAME>" | Select-Object -Last 10
   ```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-workstation-audit">✓ Origin IP Isolated</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-workstation-audit" markdown>

#### Step 2: Client Workstation Cached Credential Audit

Once the offending endpoint is identified, investigate persistent cached credential stores that repeatedly submit stale passwords in the background:

```powershell
# 1. Audit Windows Credential Manager entries
cmdkey /list

# 2. Audit persistent mapped network drives (SMB)
net use

# 3. Audit running Windows Services using user service accounts
Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -match '<USERNAME>' } |
    Select-Object Name, DisplayName, StartName, State

# 4. Audit Scheduled Tasks configured with user credentials
Get-ScheduledTask | Where-Object { $_.Principal.UserId -match '<USERNAME>' } |
    Select-Object TaskName, TaskPath, State
```

**Where are the stale credentials stored on the endpoint?**

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-purge-credman">Windows Credential Manager / Stale Drive</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-purge-services">Windows Service or Scheduled Task</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-purge-processes">Background Process / Browser / App Token</button>
</div>

</div>

<div class="cc-node" data-id="step-purge-credman" markdown>

#### Diagnostic Branch: Purge Credential Manager & Stale Drives

Purge the cached generic and domain credentials causing background authentication rejections:

```cmd
:: Delete stale network drive mappings
net use * /delete /y

:: Delete specific stale domain target from Credential Manager
cmdkey /delete:targetname=<TARGET_DOMAIN_RESOURCE>
```

```powershell
# Purge all Kerberos tickets on the client session
klist purge
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-ad-audit">✓ Credentials Purged & Proceed</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-purge-services" markdown>

#### Diagnostic Branch: Reconfigure Service & Task Credentials

Update services or tasks configured with expired user credentials:

```powershell
# Update service password or convert to Group Managed Service Account (gMSA)
$Service = Get-CimInstance Win32_Service -Filter "Name='<SERVICE_NAME>'"
$Service | Invoke-CimMethod -MethodName Change -Arguments @{ StartPassword = '<NEW_PASSWORD>' }

# Disable misconfigured user scheduled tasks
Disable-ScheduledTask -TaskName '<TASK_NAME>'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-ad-audit">✓ Service/Task Updated</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-purge-processes" markdown>

#### Diagnostic Branch: Isolate Background Apps & Mobile Tokens

1. **Terminate background processes** retaining stale cached NTLM tokens (e.g., legacy messaging clients, Outlook, custom utilities):
   ```powershell
   Get-Process -IncludeUserName | Where-Object { $_.UserName -match '<USERNAME>' }
   ```
2. **Revoke ActiveSync device partnerships** in Exchange/M365 if a mobile phone is sending an old password:
   ```powershell
   Get-MobileDevice -Mailbox '<USERNAME>' | Select-Object DeviceType, DeviceModel, DeviceId, FirstSyncTime
   ```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-ad-audit">✓ Process/Device Remediated</button>
<button type="button" class="cc-branch-btn cc-branch-btn--reset">↺ Restart Triage</button>
</div>

</div>

<div class="cc-node" data-id="step-ad-audit" markdown>

#### Step 3: Account State Audit & Safe Unlock

Verify account attributes, ensure `BadPwdCount` resets, and unlock the user account:

```powershell
# Query current account state across Domain Controllers
Get-ADUser -Identity '<USERNAME>' -Properties LockedOut, BadPwdCount, badPasswordTime, LastBadPasswordAttempt, AccountLockoutTime |
    Select-Object SamAccountName, LockedOut, BadPwdCount, LastBadPasswordAttempt, AccountLockoutTime

# Safely unlock the account
Unlock-ADAccount -Identity '<USERNAME>'
```

```powershell
# Or run with the Command & Code automated utility
.\scripts\powershell\FUNC_PS_UNLOCK_ACCOUNT.ps1 -Identity '<USERNAME>' -TargetEnvironment 'Prod'
```

<div class="cc-branch-group">
<button type="button" class="cc-branch-btn cc-branch-btn--success" data-next="step-resolved">✓ BadPwdCount = 0 & Account Unlocked</button>
<button type="button" class="cc-branch-btn cc-branch-btn--danger" data-next="step-pdc-event">✗ Account Re-Locked Immediately</button>
</div>

</div>

<div class="cc-node" data-id="step-resolved" markdown>

#### Resolution Confirmed

The root cause source (workstation cached credentials, stale drive mapping, or mobile EAS loop) has been cleared, `BadPwdCount` is reset, and the account remains active without recurring lockouts.

</div>

</div>

---

## 2. Active Directory Domain Lockout Policies

Inspect the effective domain password and account lockout policy:

```powershell
Get-ADDefaultDomainPasswordPolicy |
    Select-Object LockoutDuration, LockoutObservationWindow, LockoutThreshold, ComplexityEnabled, MinPasswordLength
```

| Policy Setting | Recommended Baseline | Operational Impact |
| :--- | :--- | :--- |
| **`LockoutThreshold`** | 5 to 10 attempts | Number of invalid attempts before account locks. Setting to 0 disables lockout (vulnerable to brute-force). |
| **`LockoutDuration`** | 15 to 30 minutes | Duration an account remains locked before auto-unlocking. |
| **`LockoutObservationWindow`** | 15 to 30 minutes | Time window before `BadPwdCount` resets to 0 after an unsuccessful attempt. Must be $\le$ `LockoutDuration`. |

---

## 3. Quick Reference: Security Event IDs for Lockouts

| Event ID | Log Name | Location | Operational Meaning |
| :--- | :--- | :--- | :--- |
| **4740** | Security | PDC Emulator | **A user account was locked out.** Contains `TargetUserName` and `CallerComputerName`. |
| **4771** | Security | All DCs | **Kerberos Pre-Authentication failed.** Failure Code `0x18` = wrong password; `0x12` = account locked. |
| **4768** | Security | All DCs | **Kerberos TGT Request.** Result code `0x6` = user not found; `0x12` = account disabled/locked. |
| **4776** | Security | All DCs | **Domain Controller attempted NTLM credential validation.** Status `0xC000006A` = bad password; `0xC0000234` = locked. |
| **4625** | Security | Origin Host / DC | **An account failed to log on.** Sub-status `0xC000006A` (bad password), `ProcessName` identifies the culprit app. |

---

## 4. Related Workflows & Tooling

- [Failed Authentication Investigation](../investigation/failed-authentication.md)
- [Active Directory Domain Management](../administration/active-directory-domain-management.md)
- [User Lifecycle Management](../administration/user-lifecycle-management.md)
- [Windows Event IDs Reference](../../references/windows-event-ids.md)
- [PowerShell Toolbox — FUNC_PS_UNLOCK_ACCOUNT.ps1](../../toolbox/powershell.md)
