---
title: Windows Advanced Audit Policy & SACLs
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
  - CMD
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - windows
  - audit-policy
  - auditpol
  - sacl
  - security-events
---

# Windows Advanced Audit Policy & SACLs

Advanced security auditing subcategories, command-line process auditing, PowerShell script block logging, and System Access Control Lists (SACLs) on sensitive files and registry hives.

## 1. Process & Service First: Event Log Subsystem

```powershell
# Windows Event Log service (EventLog) is core to security audit ingestion
Get-Service -Name EventLog | Select-Object Name, Status, StartType

# Verify active auditing subcategories via auditpol
auditpol /get /category:*
```

## 2. Advanced Audit Policy Baseline

```cmd
:: 1. Enable Process Creation & Process Termination auditing (Success)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:disable

:: 2. Enable Detailed Logon/Logoff auditing (Success and Failure)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

:: 3. Enable Sensitive Privilege Use and Kerberos Authentication
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

## 3. Process Creation Command-Line Logging

Enable command-line argument auditing for Event 4688:

```powershell
# Configure via Registry (equivalent to GPO Computer Configuration > Administrative Templates > System > Audit Process Creation)
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force }
Set-ItemProperty -Path $RegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
```

## 4. System Access Control Lists (SACLs) for Object Access

Configure SACLs to generate Event 4663 when unprivileged users touch sensitive directories or registry keys:

```powershell
# Add audit rule for Everyone on sensitive folder
$TargetDir = "C:\CorporateSecrets"
$Acl = Get-Acl -Path $TargetDir -Audit
$AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone",
    "Write, Delete, ChangePermissions",
    "ContainerInherit, ObjectInherit",
    "None",
    "Success, Failure"
)
$Acl.AddAuditRule($AuditRule)
Set-Acl -Path $TargetDir -AclObject $Acl
```
