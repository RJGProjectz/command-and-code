---
title: Local User and Group Administration
type: workflow
platforms:
  - Windows
  - Windows Server
  - Linux
languages:
  - PowerShell
  - CMD
  - Bash
tasks:
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - local-users
  - groups
  - administrators
  - sudoers
  - password-policy
  - account-security
---

# Local User and Group Administration

Operating system guide for provisioning, auditing, locking, and deleting local user accounts and managing privileged group memberships across Windows and Linux.

---

## 1. Windows Local Account Administration

### PowerShell Operations
Create, inspect, lock, and manage local accounts using `Microsoft.PowerShell.LocalAccounts`:

```powershell
# Enumerate all local user accounts with status and description
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet, PasswordExpires, LastLogon, Description

# Create a new local user with non-expiring password
$Password = Read-Host -AsSecureString "Enter password"
New-LocalUser -Name "svc-local-backup" -Password $Password -Description "Local backup agent service account" -PasswordNeverExpires

# Disable an active local account
Disable-LocalUser -Name "svc-local-backup"

# Enable and unlock a locked local account
Enable-LocalUser -Name "svc-local-backup"
Set-LocalUser -Name "svc-local-backup" -AccountExpires (Get-Date).AddDays(90)

# Enumerate members of the local Administrators group
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, ObjectClass

# Add a domain or local user to the local Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "CORP\DesktopAdmins"

# Remove an unauthorized user from local Administrators
Remove-LocalGroupMember -Group "Administrators" -Member "testuser"
```

### Windows CMD Operations
Legacy command-line operations compatible with Windows RE and WinPE environments:

```bat
:: List all local users
net user

:: View detailed properties for a specific user
net user Administrator

:: Create a new local user with password
net user operator P@ssw0rd2026! /add /comment:"Operations User" /expires:never

:: Add user to local Administrators group
net localgroup Administrators operator /add

:: View members of the local Administrators group
net localgroup Administrators

:: Disable an account
net user operator /active:no

:: Force password change on next logon
net user operator /logonpasswordchg:yes
```

---

## 2. Linux Local Account Administration

### User Provisioning & Password Management
Manage user accounts with `useradd`, `usermod`, and `passwd`:

```bash
# List all human accounts with login shells (UID >= 1000)
awk -F: '($3 >= 1000 && $1 != "nobody") {print $1, $3, $6, $7}' /etc/passwd

# Create a dedicated system service user with nologin shell
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/appsvc -m appsvc

# Create an interactive administrative user with home directory and bash
sudo useradd -m -s /bin/bash -c "DevOps Engineer" jdoe

# Set or change account password
sudo passwd jdoe

# Check password aging and expiry status for an account
sudo chage -l jdoe

# Enforce password expiration after 90 days with 7-day warning
sudo chage -M 90 -W 7 jdoe

# Lock an account (prepends ! to password hash in /etc/shadow)
sudo usermod -L jdoe

# Unlock an account
sudo usermod -U jdoe

# Expire account immediately to prevent further logins
sudo usermod --expiredate 1 jdoe
```

### Privileged Group & Sudoers Management

```bash
# List all groups the current user belongs to
id

# Add user to the sudo group (Ubuntu/Debian) or wheel group (RHEL/CentOS)
sudo usermod -aG sudo jdoe
# On RHEL/AlmaLinux/Rocky Linux:
# sudo usermod -aG wheel jdoe

# Enumerate all users in the sudo / wheel groups
getent group sudo
getent group wheel

# Create an isolated drop-in sudoers rule for a specific command without password
echo "jdoe ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart nginx" | sudo tee /etc/sudoers.d/jdoe-nginx
sudo chmod 0440 /etc/sudoers.d/jdoe-nginx

# Validate sudoers syntax before applying changes
sudo visudo -c
```

---

## 3. Security Auditing & Governance Checklist

| Audit Objective | Windows Command | Linux Command |
|:---|:---|:---|
| **Find Empty Passwords** | `Get-LocalUser \| Where-Object { -not $_.PasswordRequired }` | `sudo awk -F: '($2 == "") {print $1}' /etc/shadow` |
| **Find Inactive Accounts (>90d)** | `Get-LocalUser \| Where-Object { $_.LastLogon -lt (Get-Date).AddDays(-90) }` | `sudo lastlog -b 90` |
| **Audit Admin Membership** | `Get-LocalGroupMember -Group 'Administrators'` | `getent group sudo; getent group wheel` |
| **Verify Password Policy** | `net accounts` | `sudo grep -E 'PASS_MAX_DAYS\|PASS_MIN_LEN' /etc/login.defs` |
