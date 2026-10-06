---
title: Sysadmin Quick Reference Cheat Sheet
type: reference
platforms: [Windows, Windows Server, Linux, Microsoft 365, Entra ID]
languages: [PowerShell, Bash, Windows CLI]
tasks: [Administration, Troubleshooting, Investigation]
category: Reference
tags: [cheat sheet, sysadmin, commands, reference, quick lookup, windows and linux]
aliases: [sysadmin cheat sheet, admin quick reference, server management commands, sysadmin speed dial]
difficulty: basic
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# Sysadmin Quick Reference Cheat Sheet

A rapid lookup matrix for system administrators, engineers, and tier-2/3 support teams managing hybrid Windows and Linux infrastructure.

---

## 1. Host Identity & System Information

| Operation | Windows (PowerShell) | Linux (Bash) |
| :--- | :--- | :--- |
| **Hostname & FQDN** | `$env:COMPUTERNAME`; `[System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName` | `hostname -f` |
| **OS & Kernel Version** | `(Get-CimInstance Win32_OperatingSystem).Caption` | `cat /etc/os-release`; `uname -r` |
| **Uptime & Boot Time** | `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` | `uptime -p`; `who -b` |
| **CPU & Core Count** | `Get-CimInstance Win32_Processor \| Select-Object Name, NumberOfCores, NumberOfLogicalProcessors` | `lscpu \| grep -E 'Model name\|Socket\|Core\|Thread'` |
| **Total & Free RAM** | `Get-CimInstance Win32_OperatingSystem \| Select-Object TotalVisibleMemorySize, FreePhysicalMemory` | `free -h` |
| **Serial / BIOS / UUID** | `Get-CimInstance Win32_Bios \| Select-Object SerialNumber, Manufacturer, SMBIOSBIOSVersion` | `sudo dmidecode -s system-serial-number` |

---

## 2. Service & Daemon Management

| Action | Windows (PowerShell) | Linux (systemd) |
| :--- | :--- | :--- |
| **List Running Services** | `Get-Service \| Where-Object Status -eq 'Running'` | `systemctl list-units --type=service --state=running` |
| **Check Service Status** | `Get-Service -Name <SERVICE_NAME>` | `systemctl status <service_name>` |
| **Restart a Service** | `Restart-Service -Name <SERVICE_NAME> -Force` | `sudo systemctl restart <service_name>` |
| **Enable on Boot** | `Set-Service -Name <SERVICE_NAME> -StartupType Automatic` | `sudo systemctl enable <service_name>` |
| **Disable on Boot** | `Set-Service -Name <SERVICE_NAME> -StartupType Disabled` | `sudo systemctl disable <service_name>` |
| **Find Failed Services** | `Get-Service \| Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }` | `systemctl --failed` |

---

## 3. Storage, Filesystems & Disk Space

| Operation | Windows (PowerShell) | Linux (Bash) |
| :--- | :--- | :--- |
| **Volume Free Space** | `Get-Volume \| Format-Table DriveLetter, FileSystemLabel, SizeRemaining, Size` | `df -hT --exclude-type=tmpfs --exclude-type=devtmpfs` |
| **Disk Partitions** | `Get-Disk; Get-Partition` | `lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINT` |
| **Top 10 Largest Folders** | `Get-ChildItem -Path C:\ -Directory \| ForEach-Object { [PSCustomObject]@{ Path = $_.FullName; SizeGB = [math]::Round((Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue \| Measure-Object -Property Length -Sum).Sum / 1GB, 2) } } \| Sort-Object SizeGB -Descending \| Select-Object -First 10` | `sudo du -ahx / 2>/dev/null \| sort -rh \| head -n 10` |
| **SMART Health Status** | `Get-PhysicalDisk \| Select-Object DeviceId, FriendlyName, MediaType, OperationalStatus, HealthStatus` | `sudo smartctl -H /dev/sda` |

---

## 4. Network Connections & Port Diagnostics

| Operation | Windows (PowerShell) | Linux (Bash) |
| :--- | :--- | :--- |
| **IP & Subnet Configuration** | `Get-NetIPAddress -AddressFamily IPv4 \| Select-Object InterfaceAlias, IPAddress, PrefixLength` | `ip -brief address show` |
| **Default Gateway & Routes** | `Get-NetRoute -DestinationPrefix '0.0.0.0/0'` | `ip route show` |
| **Listening Ports & PID** | `Get-NetTCPConnection -State Listen \| Select-Object LocalAddress, LocalPort, OwningProcess` | `sudo ss -tulpn` |
| **Test Port Connectivity** | `Test-NetConnection -ComputerName '<TARGET_HOST>' -Port 443` | `nc -zvw3 '<TARGET_HOST>' 443` |
| **Flush DNS Cache** | `Clear-DnsClientCache` | `sudo resolvectl flush-caches` |
| **Trace Route to Host** | `Test-NetConnection -ComputerName '<TARGET_HOST>' -TraceRoute` | `traceroute -n '<TARGET_HOST>'` |

---

## 5. Active Directory & User Operations

### Quick Active Directory Queries (PowerShell)

```powershell
# 1. Unlock locked user account
Unlock-ADAccount -Identity '<USER>'

# 2. Check password expiration date
Get-ADUser -Identity '<USER>' -Properties "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object Name, @{N="PasswordExpires";E={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}

# 3. Find all enabled users who have not logged on in 90 days
$Cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $Cutoff } |
    Select-Object SamAccountName, LastLogonDate

# 4. List all Domain Controllers and FSMO role owners
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
```

---

## 6. Emergency Reboot & Shutdown Recipes

| Objective | Windows | Linux |
| :--- | :--- | :--- |
| **Scheduled Restart (1 min)** | `shutdown /r /t 60 /c "Scheduled maintenance"` | `sudo shutdown -r +1 "Scheduled maintenance"` |
| **Cancel Scheduled Restart** | `shutdown /a` | `sudo shutdown -c` |
| **Immediate Force Reboot** | `Restart-Computer -Force` | `sudo reboot -f` |
| **Power Off Host** | `Stop-Computer -Force` | `sudo poweroff` |

---

## Related

- [Cross-Platform Equivalents](equivalents.md)
- [PowerShell Admin Cheat Sheet](powershell-cheat-sheet.md)
- [Linux Sysadmin Speed Dial](linux-cheat-sheet.md)
- [Windows Connectivity Troubleshooting](../tasks/troubleshooting/windows-connectivity.md)
- [Linux Service Failure](../tasks/troubleshooting/linux-service-failure.md)
