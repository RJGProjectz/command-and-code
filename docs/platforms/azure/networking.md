---
title: Azure Networking (VNets, NSGs, Flow Logs, Firewall)
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Troubleshooting, Investigation, Hardening]
category: Networking
tags: [azure, vnet, nsg, network security group, flow logs, azure firewall, public ip, private endpoint, network watcher]
aliases: [azure nsg rules, azure effective security rules, azure open ports internet, azure vnet flow logs, azure public ip list, azure ip flow verify]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Azure Networking (VNets, NSGs, Flow Logs, Firewall)

Traffic to an Azure VM passes, in order: the **subnet NSG**, then the **NIC NSG** (inbound; the order reverses outbound). Routing is set by **user-defined routes**, often through **Azure Firewall** or a third-party appliance. Network Watcher tools tell you which rule allowed or blocked a flow without guessing.

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**.

## 1. Inventory

```bash
az network vnet list --query "[].{name:name, rg:resourceGroup, space:addressSpace.addressPrefixes}" -o table
az network vnet subnet list -g <rg> --vnet-name <vnet> --query "[].{name:name, prefix:addressPrefix, nsg:networkSecurityGroup.id, rt:routeTable.id}" -o table
az network vnet peering list -g <rg> --vnet-name <vnet> -o table
az network public-ip list --query "[].{name:name, ip:ipAddress, attached:ipConfiguration.id}" -o table
az network private-endpoint list -o table
```

## 2. NSG rules

```bash
az network nsg list --query "[].{name:name, rg:resourceGroup}" -o table
az network nsg rule list -g <rg> --nsg-name <nsg> --include-default \
  --query "sort_by([], &priority)[].{p:priority, name:name, dir:direction, access:access, src:sourceAddressPrefix, dport:destinationPortRange, proto:protocol}" -o table
```

**Default rules** (priority 65000+) allow traffic inside the VNet and from the Azure load balancer and deny everything else inbound. Outbound to the internet is **allowed by default**.

### Find management ports open to the internet

```kusto
// Resource Graph: NSG rules allowing RDP/SSH/WinRM from any source
Resources
| where type == "microsoft.network/networksecuritygroups"
| mv-expand rule = properties.securityRules
| extend access = tostring(rule.properties.access), direction = tostring(rule.properties.direction),
         src = tostring(rule.properties.sourceAddressPrefix), port = tostring(rule.properties.destinationPortRange)
| where access == "Allow" and direction == "Inbound" and src in ("*", "Internet", "0.0.0.0/0")
| where port in ("*", "22", "3389", "5985", "5986") or port has "-"
| project nsg = name, resourceGroup, rule = tostring(rule.name), src, port
```

## 3. Effective rules and routes on a NIC

What actually applies after subnet and NIC NSGs are merged (the VM must be running):

```bash
az network nic list-effective-nsg -g <rg> -n <nic>
az network nic show-effective-route-table -g <rg> -n <nic> -o table
```

## 4. Network Watcher: test a flow

```bash
# Would this packet be allowed? Which rule decides?
az network watcher test-ip-flow -g <rg> --vm <vm> --direction Inbound --protocol TCP \
  --local 10.0.1.4:3389 --remote 203.0.113.10:50000

# Next hop for a destination (finds UDRs, firewalls, blackholes)
az network watcher show-next-hop -g <rg> --vm <vm> --source-ip 10.0.1.4 --dest-ip 8.8.8.8

# End-to-end reachability test
az network watcher test-connectivity -g <rg> --source-resource <vm> --dest-address www.microsoft.com --dest-port 443
```

## 5. Flow logs

NSG flow logs are being retired in favor of **VNet flow logs** (new NSG flow logs cannot be created after June 30, 2025). Enable them with Traffic Analytics so they land in Log Analytics.

```bash
az network watcher flow-log list --location <region> -o table
# change: VNet flow log to a storage account with Traffic Analytics
az network watcher flow-log create --location <region> --name fl-<vnet> --vnet <vnet-id> \
  --storage-account <sa-id> --workspace <law-id> --traffic-analytics true --interval 10
```

```kusto
// Traffic Analytics: top external destinations from a host (VNet flow logs table)
NTANetAnalytics
| where TimeGenerated > ago(1d) and SrcIp == "10.0.1.4" and FlowDirection == "Outbound"
| summarize Bytes = sum(BytesSrcToDest), Flows = count() by DestIp, DestPort
| top 25 by Bytes
```

(For NSG flow logs, the table is `AzureNetworkAnalytics_CL` with `SrcIP_s`, `DestIP_s`, `DestPort_d`.)

## 6. Azure Firewall logs

```kusto
// Resource-specific tables (current); legacy deployments log to AzureDiagnostics
AZFWNetworkRule
| where TimeGenerated > ago(1h) and Action == "Deny"
| summarize count() by SourceIp, DestinationIp, DestinationPort
| top 20 by count_
```

```kusto
AZFWApplicationRule
| where TimeGenerated > ago(1d)
| summarize count() by Fqdn, Action
| order by count_ desc
```

## 7. Block or isolate (change)

```bash
# Deny all inbound from one address at top priority
az network nsg rule create -g <rg> --nsg-name <nsg> -n Deny-IR-Block --priority 100 \
  --direction Inbound --access Deny --protocol '*' --source-address-prefixes 203.0.113.10 --destination-port-ranges '*'
```

For whole-VM isolation, use the quarantine NSG in [Incident response](incident-response.md#2-isolate-a-vm).

## 8. Private access for PaaS

Storage, Key Vault and SQL are reachable from the internet by default. Use **private endpoints** plus `publicNetworkAccess: Disabled`:

```kusto
Resources
| where type in~ ("microsoft.storage/storageaccounts", "microsoft.keyvault/vaults", "microsoft.sql/servers")
| project name, type, resourceGroup, publicNetworkAccess = tostring(properties.publicNetworkAccess)
| where publicNetworkAccess !~ "Disabled"
```

## Related

- [Windows networking](../windows/networking.md) · [Linux networking](../linux/networking.md) inside the guest
- [Troubleshooting](troubleshooting.md#3-cannot-reach-a-vm)
- [Firewall and port management](../../tasks/administration/firewall-port-management.md)

## Sources

- [Network security groups: how they work](https://learn.microsoft.com/azure/virtual-network/network-security-group-how-it-works)
- [VNet flow logs](https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview)
- [Azure Firewall structured logs](https://learn.microsoft.com/azure/firewall/monitor-firewall)
