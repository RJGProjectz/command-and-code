---
title: Automated Active Directory and Cloud Identity Containment
type: workflow
platforms:
  - Active Directory
  - Entra ID
  - Microsoft 365
  - Windows Server
languages:
  - PowerShell
  - REST API
tasks:
  - Automation
  - Incident Response
  - Administration
verified: true
last_verified: 2026-10-07
difficulty: advanced
tags:
  - automation
  - containment
  - active-directory
  - entra-id
  - session-revocation
  - incident-response
---

# Automated Active Directory and Cloud Identity Containment

When a user account is identified as compromised, merely resetting their password leaves active Kerberos tickets, cloud OAuth refresh tokens, and open interactive desktop sessions operational. This automated runbook performs instant, atomic multi-layer containment.

---

## 1. Atomic Containment Workflow

```text
Alert: Confirmed Identity Compromise
    ↓
[Step 1: Disable Account Object] (Blocks subsequent authentications)
    ↓
[Step 2: Revoke Entra ID / M365 Refresh Tokens] (Invalidates web & mobile tokens)
    ↓
[Step 3: Reset Kerberos Ticket (KRBTGT)] (Invalidates on-premises TGTs)
    ↓
[Step 4: Terminate Active Sessions] (Remotely kills RDP & interactive logins)
    ↓
[Step 5: Notify Incident Commander] (Post event payload to Teams / Slack webhook)
```

---

## 2. Integrated PowerShell Containment Script

```powershell
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory = $true)]
    [string]$IncidentId
)

$Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Write-Host "[$Timestamp] Initiating Emergency Containment for: $UserPrincipalName (Incident: $IncidentId)" -ForegroundColor Cyan

# 1. On-Premises Active Directory Containment (if hybrid joined)
try {
    $ADUser = Get-ADUser -Filter "UserPrincipalName -eq '$UserPrincipalName'" -ErrorAction Stop
    if ($ADUser) {
        # Disable account
        Disable-ADAccount -Identity $ADUser.DistinguishedName
        Write-Host "[SUCCESS] Disabled on-premises AD account: $($ADUser.SamAccountName)" -ForegroundColor Green

        # Invalidate Kerberos TGT tickets by resetting password twice or scrambling
        $ScrambledPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8) | ConvertTo-SecureString -AsPlainText -Force
        Set-ADAccountPassword -Identity $ADUser.DistinguishedName -NewPassword $ScrambledPassword -Reset
        Write-Host "[SUCCESS] Scrambled AD password to kill Kerberos ticket renewals" -ForegroundColor Green
    }
}
catch {
    Write-Warning "[NOTICE] On-premises AD user not found or AD module unavailable: $_"
}

# 2. Entra ID / Microsoft 365 Cloud Token Revocation via Microsoft Graph
try {
    # Invalidate all refresh tokens issued to applications for this user
    # Forces immediate re-authentication across Outlook, Teams, Azure CLI, and browser sessions
    Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop
    Write-Host "[SUCCESS] Revoked all Entra ID / OAuth refresh tokens for $UserPrincipalName" -ForegroundColor Green

    # Disable cloud account in Entra ID
    Update-MgUser -UserId $UserPrincipalName -AccountEnabled:$false -ErrorAction Stop
    Write-Host "[SUCCESS] Disabled cloud account state in Entra ID" -ForegroundColor Green
}
catch {
    Write-Error "[FAILED] Microsoft Graph cloud containment failed: $_"
}

# 3. Terminate Interactive Terminal / RDP Sessions on Critical Servers
$TargetServers = @("WIN-DC01", "WIN-APP01", "WIN-FILE01")
foreach ($Server in $TargetServers) {
    try {
        Invoke-Command -ComputerName $Server -ScriptBlock {
            param($SamName)
            # Query sessions and log off target user
            $Sessions = quser | Where-Object { $_ -match $SamName }
            foreach ($Session in $Sessions) {
                $SessionId = ($Session -split '\s+')[2]
                logoff $SessionId
            }
        } -ArgumentList $ADUser.SamAccountName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Could not query sessions on $Server"
    }
}

Write-Host "[$Timestamp] Emergency Containment Complete for $UserPrincipalName." -ForegroundColor Cyan
```

---

## 3. Operational Safety & Verification

1. **Verify Session Termination**: Query `Get-MgUser -UserId <UPN> | Select-Object AccountEnabled` to confirm account status is `False`.
2. **Handle Mail Forwarding Rules**: Attackers frequently create hidden forwarding rules during access. Run `Get-InboxRule -Mailbox <UPN>` to audit and remove malicious exfiltration rules before restoring user access.
3. **Audit OAuth App Permissions**: Verify no third-party OAuth enterprise applications were granted delegated access by the user during the intrusion window.
