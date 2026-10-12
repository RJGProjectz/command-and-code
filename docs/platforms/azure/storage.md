---
title: Azure Storage & Data Exposure
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Storage
tags: [azure, storage account, blob, sas token, shared key, public access, immutable storage, soft delete]
aliases: [azure public blob container, azure sas token audit, azure storage account keys, rotate storage key, azure storage anonymous access, storage account exfiltration]
difficulty: intermediate
verified: false
---

# Azure Storage & Data Exposure

A storage account holds blobs, files, queues and tables behind one endpoint (`https://<account>.blob.core.windows.net`). Data exposure usually comes from one of three settings: **anonymous blob access**, **shared key / SAS tokens** that bypass Entra ID, and **public network access**.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**. Key rotation breaks every client still using the old key.

## 1. Inventory and risky settings

```bash
az storage account list --query "[].{name:name, rg:resourceGroup, kind:kind, anon:allowBlobPublicAccess, sharedKey:allowSharedKeyAccess, tls:minimumTlsVersion, net:publicNetworkAccess, defaultAction:networkRuleSet.defaultAction}" -o table
```

```kusto
// Resource Graph: accounts that allow anonymous blobs or shared keys, or are open to all networks
Resources
| where type == "microsoft.storage/storageaccounts"
| extend anon = tobool(properties.allowBlobPublicAccess), sharedKey = tobool(properties.allowSharedKeyAccess),
         defaultAction = tostring(properties.networkAcls.defaultAction), tls = tostring(properties.minimumTlsVersion)
| where anon == true or sharedKey != false or defaultAction == "Allow" or tls != "TLS1_2"
| project name, resourceGroup, subscriptionId, anon, sharedKey, defaultAction, tls
```

`allowSharedKeyAccess` is `null` (allowed) unless someone set it to `false`.

## 2. Anonymous (public) containers

```bash
az storage container list --account-name <account> --auth-mode login \
  --query "[].{name:name, public:properties.publicAccess}" -o table
```

`publicAccess` = `blob` (read blobs by URL) or `container` (also list them). Test from outside without credentials:

```bash
curl -s "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list" | head
```

Turn it off at the account (**change**); this overrides every container setting:

```bash
az storage account update -g <rg> -n <account> --allow-blob-public-access false
```

## 3. Keys and SAS tokens

Each account has two **account keys**. Anyone with a key has full data access and can mint **SAS tokens** offline, which Azure cannot list or revoke individually.

```bash
az storage account keys list -g <rg> -n <account> --query "[].{key:keyName, created:creationTime}" -o table
```

| Token type | Signed by | Revoke by |
| :--- | :--- | :--- |
| Account SAS / service SAS | Account key | Rotating the key that signed it |
| Service SAS with **stored access policy** | Account key | Deleting or changing the policy |
| **User delegation SAS** | Entra ID credentials | Revoking user delegation keys (`az storage account revoke-delegation-keys`) |

Rotate after a suspected leak (**change**):

```bash
az storage account keys renew -g <rg> -n <account> --key key1
az storage account revoke-delegation-keys -g <rg> -n <account>
```

Prevent the whole class (**change**): `az storage account update -g <rg> -n <account> --allow-shared-key-access false`, then grant data access with RBAC roles such as **Storage Blob Data Reader**.

## 4. Network access (change)

```bash
az storage account update -g <rg> -n <account> --default-action Deny
az storage account network-rule add -g <rg> --account-name <account> --ip-address 198.51.100.0/24
az storage account update -g <rg> -n <account> --public-network-access Disabled   # private endpoints only
```

## 5. Data-plane logging

Reads and writes are **not** in the Activity Log. Enable diagnostic settings for each service (blob, file, queue, table) to Log Analytics.

```kusto
// Who downloaded what, and how they authenticated
StorageBlobLogs
| where TimeGenerated > ago(1d) and OperationName == "GetBlob"
| summarize Downloads = count(), Bytes = sum(ResponseBodySize) by AccountName, CallerIpAddress, AuthenticationType, RequesterUpn
| order by Bytes desc
```

```kusto
// Anonymous or SAS access (no Entra identity)
StorageBlobLogs
| where AuthenticationType in ("Anonymous", "SAS", "AccountKey")
| summarize count() by AccountName, AuthenticationType, CallerIpAddress, bin(TimeGenerated, 1h)
```

Control-plane signs of trouble in `AzureActivity`: `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` (key read) and `MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE` (setting change).

## 6. Recovery and ransomware protection

```bash
az storage account blob-service-properties show -g <rg> -n <account> \
  --query "{softDelete:deleteRetentionPolicy, containerSoftDelete:containerDeleteRetentionPolicy, versioning:isVersioningEnabled}"
# change: 14-day soft delete and versioning
az storage account blob-service-properties update -g <rg> -n <account> \
  --enable-delete-retention true --delete-retention-days 14 --enable-versioning true
```

For backups and logs, add an **immutability policy** (time-based retention or legal hold) so even an Owner cannot delete them early. Also add a **resource lock** ([Policy & governance](policy-governance.md#3-resource-locks)).

## 7. Copy data out for analysis

```bash
azcopy login
azcopy copy "https://<account>.blob.core.windows.net/<container>/*" ./evidence/ --recursive
```

## Related

- [Keys & secrets](keys-secrets.md)
- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)
- [Backup and recovery](../../tasks/administration/backup-and-recovery.md)

## Sources

- [Prevent anonymous read access to blobs](https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent)
- [Prevent Shared Key authorization](https://learn.microsoft.com/azure/storage/common/shared-key-authorization-prevent)
- [Monitor Azure Blob Storage](https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage)
