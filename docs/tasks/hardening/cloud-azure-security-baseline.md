---
title: Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0
type: entry
platforms:
  - Azure
  - Entra ID
  - Microsoft 365
languages:
  - PowerShell
  - Bash
tasks:
  - Hardening
  - Assurance
  - Governance
verified: true
last_verified: 2026-10-06
difficulty: advanced
tags:
  - cis-benchmark
  - nist-csf
  - baseline
  - azure
  - entra-id
  - storage-account
  - key-vault
  - conditional-access
---

# Azure & Entra ID Security Baseline — CIS Benchmark & NIST CSF 2.0

Operational baseline hardening configurations for Microsoft Azure infrastructure and Entra ID tenants, aligned directly with the **CIS Microsoft Azure Foundations Benchmark (v2.0)** and **NIST Cybersecurity Framework (CSF) 2.0** (`PR.AC-01`, `PR.DS-01`, `DE.CM-01`, `GV.PO-01`).

---

## 1. Compliance Alignment Matrix

| CIS Control | NIST CSF 2.0 | Target Service | Baseline Enforcement Standard |
|:---|:---|:---|:---|
| **CIS 1.1.1** | `PR.AC-01` | Entra ID IAM | Enforce Phishing-Resistant MFA for all administrative roles; block legacy authentication. |
| **CIS 3.1** | `PR.DS-01` | Azure Storage | Enforce `Secure transfer required` (HTTPS only) and set minimum TLS to `1.2`. |
| **CIS 3.7** | `PR.DS-01` | Azure Storage | Disable anonymous public blob read access across all storage accounts. |
| **CIS 5.1** | `PR.DS-01` | Azure Key Vault | Enable `Soft Delete` and `Purge Protection` to prevent unrecoverable secret destruction. |
| **CIS 6.1** | `PR.PS-01` | Azure Networking | Restrict Network Security Groups (NSGs) to deny inbound internet access on ports 22 and 3389. |
| **CIS 2.1** | `DE.CM-01` | Defender for Cloud | Enable Defender for Cloud plan coverage across Servers, Storage, and Key Vaults. |

---

## 2. Azure Storage Account Baseline Hardening

Ensure every storage account enforces encrypted transport, TLS 1.2, and forbids public blob exposure:

### Azure CLI
```bash
RESOURCE_GROUP="rg-production-eastus"
STORAGE_ACCOUNT="stprodeast01"

# 1. Enforce HTTPS only (Secure Transfer Required) [CIS 3.1]
az storage account update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --https-only true

# 2. Enforce Minimum TLS Version 1.2 [CIS 3.1]
az storage account update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --min-tls-version TLS1_2

# 3. Disallow Anonymous Public Read Access to Blobs [CIS 3.7]
az storage account update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$STORAGE_ACCOUNT" \
  --allow-blob-public-access false
```

### Azure PowerShell (`Az`)
```powershell
$rg = "rg-production-eastus"
$account = "stprodeast01"

Set-AzStorageAccount -ResourceGroupName $rg -Name $account `
    -EnableHttpsTrafficOnly $true `
    -MinimumTlsVersion TLS1_2 `
    -AllowBlobPublicAccess $false
```

---

## 3. Azure Key Vault Hardening

Prevent ransomware or rogue operators from permanently deleting cryptographic keys, certificates, or secrets:

```bash
KEY_VAULT="kv-prod-eastus"

# Enable Soft Delete and Purge Protection [CIS 5.1 / CIS 5.2]
az keyvault update \
  --name "$KEY_VAULT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-purge-protection true
```

---

## 4. Azure Virtual Network (NSG) Inbound Hardening

Verify that subnets containing VMs do not expose management ports directly to the public internet (`0.0.0.0/0`):

```bash
NSG_NAME="nsg-workload-subnet"

# Block inbound Internet RDP (Port 3389) [CIS 6.1]
az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name "Deny-Internet-Inbound-RDP" \
  --priority 100 \
  --direction Inbound \
  --access Deny \
  --protocol Tcp \
  --source-address-prefixes Internet \
  --source-port-ranges "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 3389

# Block inbound Internet SSH (Port 22) [CIS 6.2]
az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name "Deny-Internet-Inbound-SSH" \
  --priority 110 \
  --direction Inbound \
  --access Deny \
  --protocol Tcp \
  --source-address-prefixes Internet \
  --source-port-ranges "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 22
```

---

## 5. Entra ID Conditional Access Baseline (PowerShell)

Audit Conditional Access policy enforcement for administrative MFA and legacy authentication blocks:

```powershell
# Connect-MgGraph -Scopes "Policy.Read.All"

# Query active Conditional Access policies
$policies = Get-MgIdentityConditionalAccessPolicy

# Audit for Legacy Authentication block
$legacyAuthPolicy = $policies | Where-Object { 
    $_.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or 
    $_.Conditions.ClientAppTypes -contains "other" 
}

Write-Host "Found $($legacyAuthPolicy.Count) policy/policies targeting legacy authentication protocols." -ForegroundColor Cyan
```
