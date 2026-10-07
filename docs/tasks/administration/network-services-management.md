---
title: Network Services Management
type: workflow
platforms: [Windows, Windows Server, Linux]
languages: [PowerShell, CMD, Bash]
tasks: [Administration, Troubleshooting]
category: Network
tags: [dns, dhcp, firewall, ports, bind, iptables, ufw, static ip, network configuration]
aliases: [manage dns, configure dhcp, open port, add firewall rule, create dns record, netplan]
difficulty: intermediate
verified: true
last_verified: 2026-10-06
search:
  boost: 3
---

# Network Services Management

> **Created**: 2026-10-06T18:45:00Z  
> **Last Modified**: 2026-10-06T18:45:00Z  
> **Author**: RJGProjectz  

> [!CAUTION]
> **SECURITY WARNING: VALIDATE BEFORE EXECUTION**
> Network service modifications affect host connectivity and security perimeter boundaries.
> 1. Avoid default-allow rules; restrict firewall scope to minimal authorized subnets.
> 2. Always back up DNS zone files and export firewall policies before modifying records.
> 3. Verify changes with `-WhatIf` or dry-run network flags.

**Trigger:** Server provisioning, new application deployment, DNS resolution incident, or port access change request.

**Goal:** Administer DNS records, DHCP reservations, and firewall ingress/egress filtering rules across Windows Server and Linux environments.

---

## 1. DNS Record Administration

### Windows Server DNS (`DnsServer` Module)

Query existing zone records:

```powershell
# Get all A records in an internal zone
Get-DnsServerResourceRecord -ZoneName '<INTERNAL_DOMAIN>' -RRType A |
    Select-Object HostName, @{N='IPAddress';E={$_.RecordData.IPv4Address.IPAddressToString}}
```

Create a new host `A` record and corresponding reverse lookup pointer (`PTR`):

```powershell
# Add static A record
Add-DnsServerResourceRecordA -ZoneName '<INTERNAL_DOMAIN>' `
                             -Name '<APP_HOST>' `
                             -IPv4Address '<STATIC_IP>' `
                             -CreatePtr

# Add CNAME alias record
Add-DnsServerResourceRecordCName -ZoneName '<INTERNAL_DOMAIN>' `
                                 -Name 'portal' `
                                 -HostNameAlias '<APP_HOST>.<INTERNAL_DOMAIN>'
```

### Windows Server DNS via CMD (`dnscmd.exe`)

```bat
:: Enumerate all resource records in target DNS zone
dnscmd /EnumRecords <INTERNAL_DOMAIN> @ /Type A

:: Add a static A record
dnscmd /RecordAdd <INTERNAL_DOMAIN> <APP_HOST> A <STATIC_IP>

:: Add a CNAME alias record
dnscmd /RecordAdd <INTERNAL_DOMAIN> portal CNAME <APP_HOST>.<INTERNAL_DOMAIN>

:: Delete a stale DNS record
dnscmd /RecordDelete <INTERNAL_DOMAIN> oldhost A <OLD_IP> /f
```

### Linux DNS Testing & BIND9 Query

```bash
# Test local vs upstream resolution
dig @127.0.0.1 '<APP_HOST>.<INTERNAL_DOMAIN>' +noall +answer

# Force zone transfer test (verify security restriction)
dig @'<DNS_SERVER_IP>' '<INTERNAL_DOMAIN>' AXFR
```

---

## 2. DHCP Scope & Reservation Management

### Windows Server DHCP (`DhcpServer` Module)

Audit active scope leases:

```powershell
# Retrieve leases on a target scope
Get-DhcpServerv4Lease -ScopeId '<SUBNET_ID>' |
    Select-Object IPAddress, ClientId, HostName, LeaseExpiryTime
```

Add a static DHCP reservation for a server or network printer:

```powershell
Add-DhcpServerv4Reservation -ScopeId '<SUBNET_ID>' `
                            -IPAddress '<RESERVED_IP>' `
                            -ClientId '00-15-5D-01-22-FA' `
                            -Name 'PRINTER-HQ-01' `
                            -Description 'Static lease for Finance Dept'
```

---

## 3. Host Firewall Configuration: Open & Restrict Ports

### Windows Defender Firewall

Create an inbound rule allowing HTTPS (TCP 443) only from an internal management subnet:

```powershell
$Params = @{
    DisplayName   = 'App-Inbound-HTTPS-443'
    Direction     = 'Inbound'
    Action        = 'Allow'
    Protocol      = 'TCP'
    LocalPort     = 443
    RemoteAddress = '<MANAGEMENT_SUBNET>'
    Profile       = 'Domain, Private'
    Description   = 'Allow secure web traffic from internal workstations'
}
New-NetFirewallRule @Params
```

Review and disable legacy or over-permissive allow rules:

```powershell
# Find rules allowing all remote addresses on RDP
Get-NetFirewallRule -Direction Inbound |
    Where-Object { $_.Enabled -eq 'True' -and $_.DisplayName -like '*Remote Desktop*' } |
    Get-NetFirewallAddressFilter |
    Where-Object { $_.RemoteAddress -eq 'Any' }
```

### Windows CMD Firewall Operations (`netsh.exe`)

```bat
:: Add inbound rule allowing HTTPS 443 from management subnet
netsh advfirewall firewall add rule name="App-Inbound-HTTPS-443" dir=in action=allow protocol=TCP localport=443 remoteip=<MANAGEMENT_SUBNET> profile=domain,private

:: Delete or disable a firewall rule by name
netsh advfirewall firewall set rule name="App-Inbound-HTTPS-443" new enable=no
netsh advfirewall firewall delete rule name="App-Inbound-HTTPS-443"

:: Audit all active inbound rules allowing external connections
netsh advfirewall firewall show rule name=all dir=in
```

### Linux Host Firewalls (`ufw` & `nftables`)

Ubuntu / Debian UFW:

```bash
# Allow TCP port 443 only from an authorized subnet
sudo ufw allow from '<MANAGEMENT_SUBNET>' to any port 443 proto tcp comment 'App HTTPS from LAN'

# Verify current rules with numbered index
sudo ufw status numbered
```

Direct iptables / nftables:

```bash
# Open inbound port 8443 for monitoring agent
sudo iptables -A INPUT -p tcp -s '<MANAGEMENT_SUBNET>' --dport 8443 -m comment --comment "Monitoring Inbound" -j ACCEPT

# Save persistence across reboots
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

---

## Related

- [Windows Firewall Management](../../platforms/windows/firewall.md)
- [Windows Networking and DNS](../../platforms/windows/networking.md)
- [Linux Networking and DNS](../../platforms/linux/networking.md)
- [Windows Connectivity Troubleshooting](../troubleshooting/windows-connectivity.md)
