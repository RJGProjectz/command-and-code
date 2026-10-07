---
title: Azure Cloud Infrastructure and Resource Administration
type: workflow
platforms:
  - Azure
  - Entra ID
languages:
  - PowerShell
  - Bash
tasks:
  - Administration
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - azure
  - cloud-administration
  - resource-groups
  - rbac
  - az-cli
  - tagging
---

# Azure Cloud Infrastructure and Resource Administration

Day-to-day cloud operations for managing Azure Resource Groups, lifecycle tagging, Role-Based Access Control (RBAC), and virtual machines using Azure CLI and Az PowerShell.

---

## 1. Azure CLI (`az`) Operations

```bash
# Log in to Azure and set active subscription
az login
az account set --subscription "Production-Workloads"

# Create a new Resource Group with location
az group create --name "rg-secops-prod-01" --location "eastus2"

# Apply mandatory governance tags to Resource Group
az group update --name "rg-secops-prod-01" --set tags.Environment="Production" tags.Owner="SecOps" tags.CostCenter="IT-704"

# Enumerate all virtual machines in resource group with power state
az vm list -g "rg-secops-prod-01" -d --query "[].{Name:name, State:powerState, OS:storageProfile.osDisk.osType}" -o table

# Assign an RBAC role to a user on a specific Resource Group
az role assignment create --assignee "jdoe@contoso.com" \
    --role "Reader" \
    --resource-group "rg-secops-prod-01"
```

---

## 2. Az PowerShell Operations

```powershell
# Authenticate and set context
Connect-AzAccount
Set-AzContext -SubscriptionName "Production-Workloads"

# Inspect Resource Groups and assigned tags
Get-AzResourceGroup | Select-Object ResourceGroupName, Location, Tags

# List RBAC role assignments on a target resource group
Get-AzRoleAssignment -ResourceGroupName "rg-secops-prod-01" | Select-Object DisplayName, RoleDefinitionName, Scope

# Start or stop a virtual machine
Stop-AzVM -ResourceGroupName "rg-secops-prod-01" -Name "vm-secops-collector" -Force
```
