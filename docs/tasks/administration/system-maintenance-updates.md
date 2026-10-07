---
title: System Maintenance and Updates
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, CMD, Bash]
tasks: [Administration, Automation]
category: Operations
tags: [patching, updates, reboot, maintenance, apt, dnf, pswindowsupdate, uptime]
aliases: [windows updates, linux patching, pending reboot, system maintenance, reboot server, automated updates]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# System Maintenance and Updates

> **Created**: 2026-10-06T18:45:00Z  
> **Last Modified**: 2026-10-06T18:45:00Z  
> **Author**: RJGProjectz  

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Updating packages and rebooting hosts disrupts running services.
> 1. Schedule update windows during pre-approved maintenance periods.
> 2. Confirm backup/snapshot health prior to executing kernel or cumulative OS updates.
> 3. Verify pending reboot state before attempting additional software installations.

**Trigger:** Monthly patching cycle (Patch Tuesday), critical Zero-Day CVE remediation, or periodic operational maintenance window.

**Goal:** Audit, install, and orchestrate operating system updates and required restarts safely with zero service regression.

---

## 1. Windows Server Update Orchestration

### Step 1: Check Pending Reboot Status

Before initiating an update or service restart, determine whether an earlier installation requires a reboot:

```powershell
$RebootPending = @()

# 1. Component Based Servicing (CBS)
if (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction SilentlyContinue) {
    $RebootPending += 'CBS RebootPending'
}

# 2. Windows Update Auto Update
if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue) {
    $RebootPending += 'WindowsUpdate RebootRequired'
}

# 3. Pending File Rename Operations
$RenameOps = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
if ($RenameOps) {
    $RebootPending += 'PendingFileRenameOperations'
}

if ($RebootPending.Count -gt 0) {
    Write-Warning "Reboot pending on host: $($RebootPending -join ', ')"
} else {
    Write-Output "Host has no pending reboot flags."
}
```

### Step 2: Scan and Install Updates via PSWindowsUpdate

```powershell
# Install module if missing
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Force -SkipPublisherCheck -Scope AllUsers
}

# Scan for approved missing security and critical updates
Get-WindowsUpdate -MicrosoftUpdate -Category 'SecurityUpdates', 'CriticalUpdates'

# Install updates without immediate reboot
Install-WindowsUpdate -MicrosoftUpdate -Category 'SecurityUpdates', 'CriticalUpdates' -AcceptAll -IgnoreReboot
```

### Windows CMD Maintenance & Component Repair

Native command-line maintenance tools:

```bat
:: Check for pending reboot flags in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" >nul 2>&1 && echo [ALERT] CBS Reboot Pending
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" >nul 2>&1 && echo [ALERT] Windows Update Reboot Required

:: Repair corrupted component store using DISM
dism /online /cleanup-image /checkhealth
dism /online /cleanup-image /restorehealth

:: Run System File Checker to repair corrupted OS binaries
sfc /scannow

:: Trigger Windows Update orchestrator scan and background download
usoclient StartInteractiveScan
usoclient StartDownload

:: Schedule a safe server reboot with a 5-minute notification grace period
shutdown /r /t 300 /c "Scheduled monthly maintenance reboot in 5 minutes. Save active sessions."

:: Abort a scheduled reboot if unexpected operational activity is detected
shutdown /a
```

---

## 2. Linux Server Package & Kernel Maintenance

### Debian / Ubuntu (`apt`)

Check available security upgrades:

```bash
sudo apt update
apt list --upgradable
```

Apply security updates without installing non-security packages:

```bash
# Install unattended-upgrades dry-run verification
sudo unattended-upgrade --dry-run -d

# Execute security updates
sudo apt-get --only-upgrade install $(apt-get --just-print upgrade | awk '/^Inst/ {print $2}')
```

Check if a reboot is required by the newly installed kernel or glibc:

```bash
if [ -f /var/run/reboot-required ]; then
    echo "[ALERT] System reboot required by package:"
    cat /var/run/reboot-required.pkgs
else
    echo "[OK] No reboot required."
fi
```

### RHEL / Rocky / AlmaLinux (`dnf`)

```bash
# Check security errata
sudo dnf check-update --security

# Apply only security-related updates
sudo dnf update --security -y

# Check if services or kernel require restart
sudo dnf needs-restarting -r
```

`needs-restarting -r` exits with return code `1` if a reboot is required to pick up kernel/glibc updates, or `0` if safe.

---

## 3. Safe Reboot Sequencing & Post-Check

When rebooting a critical server:

### Windows Server

```powershell
# Schedule graceful restart in 60 seconds with broadcast comment
shutdown /r /t 60 /c "Scheduled maintenance window patch reboot"

# Post-reboot uptime validation
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

### Linux Server

```bash
# Graceful reboot
sudo shutdown -r +2 "Scheduled system update maintenance reboot"

# Post-boot check
uptime -p
systemctl --failed
```

Verify that all system services returned to the active state (`systemctl --failed` returns 0 failed units).

---

## Related

- [Linux Services with systemd](../../platforms/linux/systemd.md)
- [Linux Packages](../../platforms/linux/packages.md)
- [Windows Services](../../platforms/windows/services.md)
- [Linux Troubleshooting Commands](../../platforms/linux/troubleshooting.md)
