---
title: Fundamentals — DHCP Protocol Mechanics & IP Allocation
type: entry
platforms:
  - Windows Server
  - Linux
languages:
  - PowerShell
  - Bash
tasks:
  - Troubleshooting
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: basic
tags:
  - dhcp
  - networking
  - dora
  - ip-allocation
---

# Fundamentals — DHCP Protocol Mechanics & IP Allocation

Dynamic Host Configuration Protocol (DHCP) operates over UDP ports 67 (server) and 68 (client), dynamically leasing IPv4 addresses and network configuration parameters.

## 1. The DORA Exchange Flow

```text
[Client :68] ──(1) DHCPDISCOVER (Broadcast 255.255.255.255)──► [Server :67]
[Client :68] ◄──(2) DHCPOFFER (Unicast/Broadcast + Proposed IP)── [Server :67]
[Client :68] ──(3) DHCPREQUEST (Formal Request for Offered IP)─► [Server :67]
[Client :68] ◄──(4) DHCPACK (Lease Confirmation & Options)────── [Server :67]
```

## 2. Essential DHCP Options

| Option Code | Name | Description |
| :--- | :--- | :--- |
| **Option 3** | Router | Default gateway IP address |
| **Option 6** | Domain Name Server | Primary and secondary recursive DNS servers |
| **Option 15** | Domain Name | Connection-specific DNS suffix (e.g. `corp.example.com`) |
| **Option 66 / 67** | Boot Server / Bootfile | PXE network boot TFTP server address and filename |

---

## 3. Security Threats & Attacks

- **Rogue DHCP Server** ([T1557](https://attack.mitre.org/techniques/T1557/)): Attacker deploys a rogue server responding faster than the legitimate server, handing out a compromised default gateway (MITM) and DNS server. **Mitigation**: Enable **DHCP Snooping** on switch ports.
- **DHCP Starvation**: Attacker spoofs MAC addresses to exhaust all available pool leases. **Mitigation**: Port Security (MAC limiting).

---

## 4. Diagnostics & Live Queries

```powershell
# Windows: Release and renew lease
ipconfig /release
ipconfig /renew
Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object DHCPEnabled | Select-Object Description, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires
```

```bash
# Linux: Force lease renewal via NetworkManager or dhclient
dhclient -v -r eth0 && dhclient -v eth0
journalctl -u NetworkManager --grep="DHCP4" -n 20
```
