---
title: Azure Key Vault (Keys, Secrets & Certificates)
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Secrets
tags: [azure, key vault, secrets, keys, certificates, access policy, rbac, soft delete, purge protection]
aliases: [azure key vault access policy vs rbac, who read key vault secret, rotate key vault secret, key vault purge protection, key vault firewall, list key vault secrets]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Azure Key Vault (Keys, Secrets & Certificates)

Key Vault stores **secrets** (passwords, connection strings), **keys** (RSA/EC, software or HSM-backed) and **certificates**. A vault uses one of two permission models. The model decides who can read secrets and how you audit it.

| Model | Who can read secrets | Recommended |
| :--- | :--- | :--- |
| **Azure RBAC** (`enableRbacAuthorization: true`) | Principals with a data-plane role (Key Vault Secrets User, Secrets Officer, Administrator) | Yes |
| **Vault access policy** (legacy) | Principals listed in the vault's access policies. Anyone with **Contributor** on the vault can add themselves. | No; migrate |

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Commands that change state are marked **change**. Never print secret values into terminals that are logged or recorded.

## 1. Inventory and settings

```bash
az keyvault list --query "[].{name:name, rg:resourceGroup}" -o table
az keyvault show -n <vault> --query "{rbac:properties.enableRbacAuthorization, softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection, retentionDays:properties.softDeleteRetentionInDays, publicNetwork:properties.publicNetworkAccess, defaultAction:properties.networkAcls.defaultAction}"
```

```kusto
// Resource Graph: vaults still on access policies, without purge protection, or open to all networks
Resources
| where type == "microsoft.keyvault/vaults"
| extend rbac = tobool(properties.enableRbacAuthorization), purge = tobool(properties.enablePurgeProtection),
         defaultAction = tostring(properties.networkAcls.defaultAction)
| where rbac != true or purge != true or defaultAction != "Deny"
| project name, resourceGroup, subscriptionId, rbac, purge, defaultAction
```

## 2. Who can read secrets?

```bash
# RBAC vaults: data-plane roles on the vault (and inherited)
az role assignment list --scope $(az keyvault show -n <vault> --query id -o tsv) --include-inherited \
  --query "[?contains(roleDefinitionName,'Key Vault')].{p:principalName, role:roleDefinitionName, scope:scope}" -o table

# Access-policy vaults
az keyvault show -n <vault> --query "properties.accessPolicies[].{objectId:objectId, secrets:permissions.secrets, keys:permissions.keys}" -o json
```

## 3. List and read (metadata first)

```bash
az keyvault secret list --vault-name <vault> --query "[].{name:name, enabled:attributes.enabled, expires:attributes.expires, updated:attributes.updated}" -o table
az keyvault secret list-versions --vault-name <vault> -n <secret> -o table
az keyvault key list --vault-name <vault> -o table
az keyvault certificate list --vault-name <vault> --query "[].{name:name, expires:attributes.expires}" -o table

# Value (only when needed)
az keyvault secret show --vault-name <vault> -n <secret> --query value -o tsv
```

```powershell
Get-AzKeyVaultSecret -VaultName <vault> | Select-Object Name, Enabled, Expires, Updated
Get-AzKeyVaultSecret -VaultName <vault> -Name <secret> -AsPlainText   # only when needed
```

## 4. Create, rotate and disable (change)

```bash
az keyvault secret set --vault-name <vault> -n db-password --file ./new-secret.txt --expires 2027-01-01T00:00:00Z
az keyvault secret set-attributes --vault-name <vault> -n <secret> --enabled false      # stop it being used
az keyvault key rotate --vault-name <vault> -n <key>
az keyvault key rotation-policy show --vault-name <vault> -n <key>
```

Passing secrets with `--file` keeps them out of shell history; `--value` does not.

## 5. Soft delete and purge protection

Soft delete is always on for new vaults (7–90 days). **Purge protection** stops anyone, including an attacker with Owner, from permanently deleting the vault or its objects before retention ends. Enable it (**change**, cannot be turned off):

```bash
az keyvault update -n <vault> --enable-purge-protection true
az keyvault list-deleted -o table
az keyvault secret list-deleted --vault-name <vault> -o table
az keyvault secret recover --vault-name <vault> -n <secret>     # change
```

## 6. Network restriction (change)

```bash
az keyvault update -n <vault> --default-action Deny --bypass AzureServices
az keyvault network-rule add -n <vault> --ip-address 198.51.100.0/24
az keyvault update -n <vault> --public-network-access Disabled    # private endpoint only
```

## 7. Audit secret access

Data-plane access is only logged once a diagnostic setting sends `AuditEvent` to Log Analytics.

```kusto
// Who read secrets, from where (AzureDiagnostics schema; resource-specific table is AZKVAuditLogs)
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName in ("SecretGet", "SecretList", "KeyDecrypt", "KeyUnwrap")
| summarize Ops = count(), Secrets = make_set(id_s, 20) by Resource, identity_claim_upn_s, identity_claim_appid_g, CallerIPAddress, OperationName
| order by Ops desc
```

```kusto
// Bulk reads: one caller pulling many distinct secrets in an hour
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| summarize Distinct = dcount(id_s) by Resource, CallerIPAddress, identity_claim_appid_g, bin(TimeGenerated, 1h)
| where Distinct > 10
```

Control-plane changes (access-policy edits, network changes) are in `AzureActivity` as `MICROSOFT.KEYVAULT/VAULTS/WRITE` and `.../ACCESSPOLICIES/WRITE`.

## Related

- [Identity & access](identity-access.md)
- [Certificate and PKI management](../../tasks/administration/certificate-and-pki-management.md)
- [CI/CD secret leak detection](../../detection/sigma/cicd-secret-leak.md)
- [Store service secrets on Linux](../../tasks/administration/linux-service-secrets-storage.md) · [on Windows](../../tasks/administration/windows-service-secrets-storage.md) (reading the secret from a VM with its own identity)

## Sources

- [Key Vault RBAC guide](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
- [Soft delete and purge protection](https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview)
- [Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)
