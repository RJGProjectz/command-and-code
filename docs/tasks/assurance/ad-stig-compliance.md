---
title: Assurance Check — Active Directory STIG Compliance
type: entry
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - assurance
  - active-directory
  - stig
  - compliance
---

# Assurance Check — Active Directory STIG Compliance

Audits Active Directory Domain Controller configurations against DISA STIG baselines, focusing on Domain Admins membership limits and password policy constraints.

## PowerShell Compliance Audit

```powershell
# 1. Audit Tier-0 Domain Admins Membership (Baseline: <= 5 accounts)
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins"
$AdminCount = ($DomainAdmins | Measure-Object).Count

if ($AdminCount -gt 5) {
    Write-Warning "[VIOLATION] Excessive Domain Admins count ($AdminCount). STIG baseline requires <= 5."
} else {
    Write-Host "[PASS] Domain Admins count is compliant ($AdminCount accounts)." -ForegroundColor Green
}

# 2. Audit Default Domain Password Policy
$Policy = Get-ADDefaultDomainPasswordPolicy
[PSCustomObject]@{
    MinPasswordLength    = $Policy.MinPasswordLength      # STIG requires >= 14
    ComplexityEnabled    = $Policy.ComplexityEnabled      # STIG requires True
    LockoutThreshold     = $Policy.LockoutThreshold       # STIG requires <= 5 attempts
    LockoutDurationMins  = $Policy.LockoutDuration.TotalMinutes
}
```
