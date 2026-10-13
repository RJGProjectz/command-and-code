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
last_verified: 2026-10-12
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
- **VNet Peering**: Low-latency private interconnect between VNets across regions without public IP routing. Peering is **not transitive**: A↔B and B↔C does not connect A to C.
- **Private Endpoints**: give a PaaS service (Storage, Key Vault, SQL) a private IP in your VNet so its public endpoint can be disabled.
- **Azure Bastion**: browser-based RDP/SSH to VMs without public IPs on the VMs.

## 2. How NSG rules are evaluated

- Rules are processed by **priority** (100–4096, lowest number first); the first match wins.
- Every NSG has default rules at priority 65000+: `AllowVnetInBound`, `AllowAzureLoadBalancerInBound`, `DenyAllInBound` (and the outbound equivalents, including `AllowInternetOutBound`). `VirtualNetwork` includes peered VNets and on-premises ranges, so "allow VNet" is wider than it looks.
- When an NSG is on both the subnet and the NIC, inbound traffic must pass the **subnet NSG, then the NIC NSG**; outbound is the reverse.
- **Service tags** (`Internet`, `AzureCloud`, `Storage.WestEurope`) stand for Microsoft-maintained IP ranges.

## 3. Common findings

| Finding | Risk | Fix |
| --- | --- | --- |
| Inbound `Any` / `Internet` on 22, 3389, 5985/5986 | Brute force and exploitation of exposed management ports | Remove; use Bastion or just-in-time VM access |
| Database ports open to `Internet` | Direct data exposure | Private endpoint; restrict to app subnet / ASG |
| Overly broad outbound `Internet` | Easy command-and-control and exfiltration | Route through Azure Firewall with application rules |
| No flow logs | Nothing to investigate with | Enable VNet flow logs to a storage account and Traffic Analytics |
| Public IPs on VMs that do not need them | Unnecessary attack surface | Remove; use NAT Gateway for outbound |

## 4. Inspect

```bash
# Rules in an NSG, including defaults
az network nsg rule list -g <resource-group> --nsg-name <nsg> --include-default -o table

# What actually applies to a VM's NIC (subnet + NIC NSGs combined)
az network nic list-effective-nsg -g <resource-group> -n <nic-name>

# Effective routes (is traffic forced through the firewall?)
az network nic show-effective-route-table -g <resource-group> -n <nic-name> -o table
```

## 5. Logs for investigations

**VNet flow logs** (Network Watcher) record allowed and denied flows for a whole VNet and replace NSG flow logs, which Microsoft is retiring. Send them to a storage account and enable Traffic Analytics to query them in Log Analytics. Azure Firewall logs (`AZFWNetworkRule`, `AZFWApplicationRule`) show what the firewall allowed or denied.

## Related

- [Azure NSG compliance check](../../tasks/assurance/azure-nsg-compliance.md)
- [Microsegmentation](../networking/microsegmentation.md)
- [Azure platform overview](../../platforms/azure/index.md)

## Sources

- [Microsoft Learn — Network security groups overview](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)
- [Microsoft Learn — How NSGs filter traffic](https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works)
- [Microsoft Learn — Virtual network flow logs](https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview)
- [Microsoft Learn — az network nic](https://learn.microsoft.com/cli/azure/network/nic)
