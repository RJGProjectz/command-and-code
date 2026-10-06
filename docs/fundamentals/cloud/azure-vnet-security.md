---
title: Fundamentals — Azure Virtual Network (VNet) Security
type: entry
platforms:
  - Azure
languages:
  - PowerShell
tasks:
  - Hardening
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: intermediate
tags:
  - azure
  - vnet
  - nsg
  - cloud-networking
---

# Fundamentals — Azure Virtual Network (VNet) Security

Azure Virtual Networks provide isolated cloud network boundary enforcement for cloud virtual machines, managed databases, and container clusters.

## 1. Network Security Controls

- **Network Security Groups (NSGs)**: Stateful 5-tuple packet filters applied at subnet or network interface (NIC) levels.
- **Application Security Groups (ASGs)**: Logical grouping of VMs allowing rules like `Allow Web-ASG to DB-ASG on Port 1433` without hardcoding IP addresses.
- **Azure Firewall**: Managed cloud-native stateful firewall with threat intelligence filtering and L7 application rules.
- **VNet Peering**: Low-latency private interconnect between VNets across regions without public IP routing.
