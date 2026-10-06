---
title: PowerShell Admin One-Liners Cheat Sheet
type: reference
platforms: [Windows, Windows Server]
languages: [PowerShell]
tasks: [Administration, Investigation, Automation]
category: Reference
tags: [powershell, cheat sheet, one-liners, administration, ad, wmi, cim, event logs]
aliases: [powershell cheat sheet, powershell one-liners, powershell admin commands, useful powershell commands]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# PowerShell Admin One-Liners Cheat Sheet

A curated collection of practical, copy-pasteable PowerShell one-liners for day-to-day systems administration, inventory, and troubleshooting.

---

## 1. System Inventory & Hardware Checks

```powershell
# Quick hardware inventory summary
[PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    Model        = (Get-CimInstance Win32_ComputerSystem).Model
    RAM_GB       = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    CPU          = (Get-CimInstance Win32_Processor).Name.Trim()
    OS           = (Get-CimInstance Win32_OperatingSystem).Caption
    LastBoot     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
}

# Find all network adapters with link speed and MAC address
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress

# Inspect physical disk drives and bus types (SSD/NVMe vs HDD)
Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, MediaType, BusType, Size, HealthStatus
```

---

## 2. Processes, Performance & File Locks

```powershell
# Top 5 processes by memory consumption (working set)
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 Name, Id, @{N='MemoryMB';E={[math]::Round($_.WorkingSet64 / 1MB, 1)}}

# Top 5 processes by total CPU utilization
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, Id, CPU

# Find process path and command line by process name
Get-CimInstance Win32_Process -Filter "Name = 'svchost.exe'" | Select-Object ProcessId, CommandLine

# Find all open SMB file shares and connected clients
Get-SmbOpenFile | Select-Object FileId, SessionId, Path, ClientUserName, ClientComputerName
```

---

## 3. Active Directory Administration Fast-Track

```powershell
# Find all members of Domain Admins (including nested groups)
Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, SamAccountName, ObjectClass

# Export all active user email addresses and titles to CSV
Get-ADUser -Filter {Enabled -eq $true} -Properties mail, title, department |
    Select-Object SamAccountName, Name, mail, title, department |
    Export-Csv -Path 'C:\Staging\UsersExport.csv' -NoTypeInformation

# Find disabled computer accounts in AD
Get-ADComputer -Filter {Enabled -eq $false} -Properties OperatingSystem | Select-Object Name, OperatingSystem

# Test AD replication status across all partners
Get-ADReplicationPartnerMetadata -Target (Get-ADDomain).DNSRoot -Scope Domain |
    Select-Object Server, Partner, LastReplicationSuccess, ConsecutiveFailureCount
```

---

## 4. Windows Event Log Parsing

```powershell
# Quick count of failed logons (Event ID 4625) over the last 24 hours
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count

# Find recent system shutdowns and unexpected restarts (Event IDs 1074, 6008)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6008; StartTime=(Get-Date).AddDays(-7)} |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap

# Search Application log for recent crashes (Event ID 1000)
Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddDays(-3)} |
    Select-Object TimeCreated, Message | Format-List
```

---

## 5. Remote Administration & PSRemoting

```powershell
# Run a quick command across multiple remote servers simultaneously
$Servers = @('SRV-APP-01', 'SRV-APP-02', 'SRV-DB-01')
Invoke-Command -ComputerName $Servers -ScriptBlock {
    [PSCustomObject]@{
        Host     = $env:COMPUTERNAME
        FreeDisk = (Get-Volume -DriveLetter C).SizeRemaining / 1GB
        Uptime   = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
} -HideComputerName

# Restart a service on a remote host
Invoke-Command -ComputerName 'SRV-APP-01' -ScriptBlock { Restart-Service -Name 'W3SVC' -Force }
```

---

## Related

- [PowerShell Fundamentals and Pitfalls](../../languages/powershell/fundamentals.md)
- [PowerShell Automation and Remoting](../../languages/powershell/automation.md)
- [Sysadmin Quick Reference](sysadmin-cheat-sheet.md)
- [Cross-Platform Equivalents](equivalents.md)
