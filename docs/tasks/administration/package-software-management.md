---
title: Package and Software Lifecycle Management
type: workflow
platforms:
  - Windows
  - Linux
languages:
  - PowerShell
  - Bash
  - CMD
tasks:
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - package-manager
  - winget
  - apt
  - dnf
  - software-inventory
  - updates
---

# Package and Software Lifecycle Management

Cross-platform operations for installing, upgrading, inventorying, and removing software applications using Windows Package Manager (`winget`) and Linux `apt` / `dnf`.

---

## 1. Windows Package Management (winget)

```powershell
# Search for an application in the official winget repository
winget search "Wireshark"

# Install application silently with accepted licenses
winget install --id "WiresharkFoundation.Wireshark" --exact --silent --accept-package-agreements --accept-source-agreements

# Enumerate installed software packages across the system
winget list

# Check for available software upgrades
winget upgrade

# Upgrade all installed packages to their latest release
winget upgrade --all --include-unknown --silent

# Uninstall an application
winget uninstall --id "WiresharkFoundation.Wireshark"
```

### Windows CMD & MSI Unattended Installation

```bat
:: Install an MSI package silently without rebooting
msiexec.exe /i "C:\Staging\endpoint-agent.msi" /qn /norestart /log "C:\Audit\install.log"

:: Silently uninstall an application using its product GUID
msiexec.exe /x {12345678-ABCD-1234-ABCD-1234567890AB} /qn /norestart

:: Enumerate installed MSI products via command prompt
wmic product get Name, Version, Vendor /format:table
```

---

## 2. Linux Package Management (Debian/Ubuntu & RHEL)

### Debian / Ubuntu (`apt` & `dpkg`)

```bash
# Update repository index lists
sudo apt update

# Install a specific package
sudo apt install -y curl htop jq

# Upgrade all installed packages to latest versions
sudo apt upgrade -y

# List installed packages matching a pattern
dpkg -l | grep -E "openssh|nginx|docker"

# Remove package while preserving configuration files
sudo apt remove -y nginx

# Purge package completely including configurations
sudo apt purge -y nginx
sudo apt autoremove -y
```

### RHEL / AlmaLinux / Rocky Linux (`dnf` & `rpm`)

```bash
# Check for available package updates
sudo dnf check-update

# Install package
sudo dnf install -y epel-release htop

# Upgrade all system packages
sudo dnf upgrade -y

# Enumerate installed RPM packages
rpm -qa | grep -E "kernel|sshd"
```
