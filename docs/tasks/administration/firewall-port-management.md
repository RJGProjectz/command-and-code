---
title: Host Firewall and Port Management
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
  - Hardening
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - firewall
  - netsh
  - ufw
  - iptables
  - ports
  - network-security
---

# Host Firewall and Port Management

Configuring, inspecting, and managing host-based packet filters and port access rules using Windows Defender Firewall, Linux UFW, and nftables.

---

## 1. Windows Defender Firewall Administration

### PowerShell `NetSecurity` Commands

```powershell
# Check state of all three firewall profiles (Domain, Private, Public)
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Ensure all firewall profiles are turned on
Set-NetFirewallProfile -All -Enabled True

# Set default inbound action to Block for all profiles
Set-NetFirewallProfile -All -DefaultInboundAction Block

# Create an inbound rule allowing TCP port 443 from internal subnet
New-NetFirewallRule -DisplayName "Allow Inbound HTTPS Admin" `
    -Direction Inbound -Protocol TCP -LocalPort 443 `
    -RemoteAddress 10.0.0.0/8 -Action Allow

# Allow inbound traffic for a specific application binary
New-NetFirewallRule -DisplayName "Allow Internal App Service" `
    -Direction Inbound -Program "C:\Program Files\App\app.exe" `
    -Action Allow

# Find all active rules allowing port 3389 (RDP)
Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -eq "3389" } | Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action

# Disable a specific rule
Disable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)"

# Delete a custom rule
Remove-NetFirewallRule -DisplayName "Allow Inbound HTTPS Admin"
```

### Windows CMD Operations

```bat
:: Check firewall status across all profiles
netsh advfirewall show allprofiles

:: Enable firewall on all profiles
netsh advfirewall set allprofiles state on

:: Add rule opening TCP port 8443
netsh advfirewall firewall add rule name="Allow WebApp Port 8443" dir=in action=allow protocol=TCP localport=8443

:: Delete rule by name
netsh advfirewall firewall delete rule name="Allow WebApp Port 8443"

:: Reset firewall to default state
netsh advfirewall reset
```

---

## 2. Linux Host Firewall Management

### UFW (Uncomplicated Firewall — Ubuntu/Debian)

```bash
# Check status and active rules
sudo ufw status verbose

# Set default policies: deny incoming, allow outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow incoming SSH with rate limiting
sudo ufw limit ssh

# Allow incoming TCP port 443 from specific subnet
sudo ufw allow from 10.0.0.0/8 to any port 443 proto tcp

# Delete a rule by its number
sudo ufw status numbered
sudo ufw delete 2

# Enable firewall
sudo ufw enable
```

### Nftables / Iptables Rule Operations

```bash
# View active nftables ruleset
sudo nft list ruleset

# Add rule allowing port 80 and 443 in nftables
sudo nft add rule inet filter input tcp dport { 80, 443 } ct state new accept

# Iptables: Inspect active input rules with packet counters
sudo iptables -L INPUT -v -n --line-numbers

# Iptables: Block incoming traffic from malicious IP
sudo iptables -I INPUT -s 198.51.100.25 -j DROP
```
