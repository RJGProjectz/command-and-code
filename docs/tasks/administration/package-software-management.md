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
  - Python
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
  - zypper
  - snap
  - flatpak
  - pip
  - npm
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

---

## 3. SUSE / openSUSE (`zypper`)

```bash
# Refresh repository metadata
sudo zypper refresh

# Search for a package by name or keyword
zypper search htop

# Install a package
sudo zypper install -y htop

# Upgrade all installed packages
sudo zypper update -y

# List installed packages matching a pattern
rpm -qa | grep -i openssh

# Remove a package
sudo zypper remove -y htop

# Show available patches (security/recommended/optional)
sudo zypper list-patches
sudo zypper patch -y
```

---

## 4. Universal Package Formats

### Snap (Ubuntu / systemd-based distros)

```bash
# Search the Snap Store
snap find "code"

# Install a snap package
sudo snap install code --classic

# List installed snaps
snap list

# Refresh all installed snaps to latest channels
sudo snap refresh

# Remove a snap
sudo snap remove code
```

### Flatpak (Flathub)

```bash
# Add the Flathub remote (first-time setup)
flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo

# Search for an application
flatpak search "vlc"

# Install from Flathub
flatpak install flathub org.videolan.VLC -y

# List installed Flatpaks
flatpak list

# Update all installed Flatpaks
flatpak update -y

# Remove a Flatpak
flatpak uninstall org.videolan.VLC -y
flatpak uninstall --unused -y   # purge orphaned runtimes
```

---

## 5. Language Package Managers

### Python (`pip` / `pip3`)

```bash
# Upgrade pip itself first
python3 -m pip install --upgrade pip

# Install a package into the current environment
pip3 install requests

# Install a specific version
pip3 install "ansible==9.5.1"

# List installed packages with versions
pip3 list

# Export installed packages to a requirements file
pip3 freeze > requirements.txt

# Install all packages from a requirements file
pip3 install -r requirements.txt

# Upgrade a specific package
pip3 install --upgrade ansible

# Uninstall
pip3 uninstall -y requests
```

> **Prefer virtual environments** (`python3 -m venv .venv && source .venv/bin/activate`) to avoid polluting the system Python interpreter.

### Node.js (`npm`)

```bash
# Install a package locally (project dependency)
npm install lodash

# Install a package globally (CLI tools)
npm install -g http-server

# List globally installed packages
npm list -g --depth=0

# Check for outdated packages
npm outdated

# Upgrade all packages in package.json within semver range
npm update

# Upgrade the npm CLI itself
npm install -g npm@latest

# Uninstall a package
npm uninstall lodash
npm uninstall -g http-server
```
