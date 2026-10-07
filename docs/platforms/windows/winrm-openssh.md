---
title: Windows Remote Access (WinRM & OpenSSH)
type: entry
platforms:
  - Windows
  - Windows Server
languages:
  - PowerShell
tasks:
  - Administration
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - windows
  - winrm
  - openssh
  - psremoting
  - remote-access
---

# Windows Remote Access (WinRM & OpenSSH)

Managing, securing, and auditing remote administrative access via Windows Remote Management (WinRM/WS-Man) and native OpenSSH Server on Windows.

## 1. Process & Service First: WinRM & SSH Daemons

```powershell
# Check service states for WinRM and OpenSSH Server
Get-Service -Name WinRM, sshd, ssh-agent | Select-Object Name, Status, StartType

# Ensure WinRM service is running and set to Automatic
Start-Service WinRM
Set-Service WinRM -StartupType Automatic
```

## 2. WinRM Configuration & Listeners

```powershell
# 1. Enumerate WinRM listeners (HTTP port 5985, HTTPS port 5986)
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate

# 2. Inspect authentication and encryption policies
Get-Item WSMan:\localhost\Service\Auth | Format-List
Get-Item WSMan:\localhost\Service\AllowUnencrypted

# 3. Create an HTTPS Listener using machine certificate
$Cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match $env:COMPUTERNAME } | Select-Object -First 1
New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{Address="*";Transport="HTTPS"} -ValueSet @{Hostname=$env:COMPUTERNAME;CertificateThumbprint=$Cert.Thumbprint}
```

## 3. Native OpenSSH for Windows

```powershell
# 1. Install and start native OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic

# 2. Configure administrative authorized_keys
# Note: For local administrators, keys reside in:
# C:\ProgramData\ssh\administrators_authorized_keys
$AdminKeyPath = "C:\ProgramData\ssh\administrators_authorized_keys"
icacls.exe $AdminKeyPath /inheritance:r /grant "SYSTEM:(F)" /grant "Administrators:(F)"
```

## 4. Hardening & Disabling Unencrypted Access

```powershell
# Disallow unencrypted traffic and basic authentication on WinRM
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
```
