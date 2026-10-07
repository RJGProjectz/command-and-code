---
title: Network Adapter and IP Configuration
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
  - networking
  - ip-address
  - dns
  - gateway
  - routing
  - adapter
---

# Network Adapter and IP Configuration

Operational guide for configuring network interfaces, static IP addressing, default gateways, DNS resolvers, and static routes on Windows and Linux endpoints.

---

## 1. Windows Network Adapter Management

### PowerShell Operations
Use the `NetTCPIP` and `DnsClient` modules for modern interface configuration:

```powershell
# Enumerate all physical and virtual network adapters
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed

# View current IP configuration on all active adapters
Get-NetIPConfiguration

# Set a static IP address, subnet prefix, and default gateway
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress "192.168.10.50" -PrefixLength 24 -DefaultGateway "192.168.10.1"

# Configure primary and secondary DNS server addresses
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses "192.168.10.10", "1.1.1.1"

# Switch adapter back to DHCP
Set-NetIPInterface -InterfaceAlias "Ethernet0" -Dhcp Enabled
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ResetServerAddresses

# Add a persistent static route
New-NetRoute -DestinationPrefix "10.50.0.0/16" -InterfaceAlias "Ethernet0" -NextHop "192.168.10.254" -RouteMetric 10

# Test TCP port connectivity to remote target
Test-NetConnection -ComputerName "10.50.1.10" -Port 443
```

### Windows CMD Operations

```bat
:: Display full IP address and adapter details
ipconfig /all

:: Set static IP address and subnet mask via netsh
netsh interface ip set address name="Ethernet0" static 192.168.10.50 255.255.255.0 192.168.10.1

:: Set primary DNS server
netsh interface ip set dns name="Ethernet0" static 192.168.10.10

:: Add secondary DNS server
netsh interface ip add dns name="Ethernet0" 1.1.1.1 index=2

:: Print active routing table
route print -4

:: Add persistent static route
route -p add 10.50.0.0 mask 255.255.0.0 192.168.10.254
```

---

## 2. Linux Network Interface Management

### Modern `iproute2` and `nmcli` Operations

```bash
# List all network links and MAC addresses
ip link show

# List all assigned IP addresses
ip -br addr show

# Temporarily assign a static IP address and subnet
sudo ip addr add 192.168.10.50/24 dev eth0

# Add a default gateway
sudo ip route add default via 192.168.10.1 dev eth0

# View kernel IP routing table
ip route show

# Configure persistent static IP using NetworkManager CLI (nmcli)
sudo nmcli con mod "Wired connection 1" ipv4.addresses "192.168.10.50/24"
sudo nmcli con mod "Wired connection 1" ipv4.gateway "192.168.10.1"
sudo nmcli con mod "Wired connection 1" ipv4.dns "192.168.10.10,1.1.1.1"
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con up "Wired connection 1"

# Query active DNS resolvers in systemd-resolved
resolvectl status
```

### Netplan Configuration (Ubuntu 20.04+)
Edit `/etc/netplan/01-netcfg.yaml` for declarative static addressing:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses:
        - 192.168.10.50/24
      routes:
        - to: default
          via: 192.168.10.1
      nameservers:
        addresses: [192.168.10.10, 1.1.1.1]
```

Apply Netplan configuration safely:
```bash
sudo netplan try
sudo netplan apply
```
