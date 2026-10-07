---
title: Active Directory Domain Services Administration
type: workflow
platforms:
  - Windows Server
  - Active Directory
languages:
  - PowerShell
  - CMD
tasks:
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - active-directory
  - domain-controller
  - computers
  - organizational-units
  - replication
  - rbac
---

# Active Directory Domain Services Administration

Core domain management procedures for managing domain-joined computer objects, organizational units (OUs), security groups, and domain controller replication health.

---

## 1. Computer Object & OU Lifecycle Management

```powershell
# Enumerate all domain computers with operating system and last logon
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | 
    Select-Object Name, OperatingSystem, LastLogonDate, Enabled | 
    Sort-Object LastLogonDate -Descending

# Find stale computer accounts inactive for over 90 days
$Cutoff = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $Cutoff -and Enabled -eq $true} -Properties LastLogonDate |
    Select-Object Name, LastLogonDate, DistinguishedName

# Move a computer account into a specific Organizational Unit
$Computer = Get-ADComputer -Identity "WKSTN-FIN-042"
Move-ADObject -Identity $Computer.DistinguishedName -TargetPath "OU=Workstations,OU=Finance,DC=corp,DC=internal"

# Reset a broken computer account secure channel password
Reset-ComputerMachinePassword
```

---

## 2. Domain Controller Replication & Health Auditing

```powershell
# Discover closest Domain Controller providing authentication
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers

# Query replication partner status and error counts
Get-ADReplicationPartnerMetadata -Target "DC01.corp.internal" -Scope Server |
    Select-Object Partner, LastReplicationSuccess, ConsecutiveFailureCount
```

### Native Domain Health CMD Tools

```bat
:: Display domain controller replication partners and errors
repadmin /showrepl

:: Force inbound replication across all directory partitions
repadmin /syncall /AdeP

:: Verify Domain Controller locator service and Kerberos KDCS
nltest /dsgetdc:corp.internal
```
