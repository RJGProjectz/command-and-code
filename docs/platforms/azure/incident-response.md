---
title: Azure Incident Response & Forensics
platforms: [Azure, Entra ID]
languages: [Bash, PowerShell, KQL]
tasks: [Incident Response, Forensics, Investigation]
category: Incident Response
tags: [azure, incident response, containment, isolate vm, disk snapshot, revoke sessions, evidence, forensics]
aliases: [isolate azure vm, snapshot azure disk for forensics, revoke azure service principal, contain azure compromise, azure ir runbook, azure evidence collection]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# Azure Incident Response & Forensics

Azure incidents usually start with a **compromised identity** (user, service principal or managed identity) and then move to **resources** (VMs, storage, Key Vault). Contain the identity first, then the resources, and preserve evidence before you rebuild anything. For the cloud-agnostic process, see [Concept: DFIR](../../fundamentals/concepts/digital-forensics.md).

!!! warning "Before you run anything"
    Every command was checked against the Azure CLI reference and Microsoft Learn (2026-10-12); this guide does not run them against a live tenant. Almost every command here **changes state**. Agree containment with the incident lead before you run it, and record each action with a UTC timestamp.

## 1. Contain the identity

=== "User"

    ```powershell
    Connect-MgGraph -Scopes 'User.ReadWrite.All'
    Update-MgUser -UserId user@contoso.com -AccountEnabled:$false
    Revoke-MgUserSignInSession -UserId user@contoso.com     # invalidates refresh tokens
    ```

    Full steps (password reset, MFA methods, mailbox rules): [Account compromise](../../tasks/incident-response/account-compromise.md).

=== "Service principal / app"

    ```bash
    az ad sp update --id <app-id> --set accountEnabled=false
    az ad app credential list --id <app-id> -o table          # find attacker-added secrets/certs
    az ad app credential delete --id <app-id> --key-id <key-id>
    ```

    See [Compromised service principal](../../tasks/incident-response/compromised-service-principal.md).

=== "Managed identity"

    A managed identity cannot be disabled. Remove its role assignments, or remove the identity from the resource:

    ```bash
    az role assignment list --assignee <principal-id> --all -o table
    az role assignment delete --assignee <principal-id> --role <role> --scope <scope>
    az vm identity remove -g <rg> -n <vm>                    # system-assigned
    ```

Access tokens already issued stay valid until they expire (about 60–90 minutes) unless the resource supports Continuous Access Evaluation. Removing role assignments takes effect on the next ARM call.

## 2. Isolate a VM

Keep the VM **running** so memory survives. Swap in a quarantine NSG that allows only your forensic jump host.

```bash
az network nsg create -g <rg> -n nsg-quarantine
az network nsg rule create -g <rg> --nsg-name nsg-quarantine -n allow-ir-in  --priority 100 --direction Inbound  --access Allow --protocol Tcp --source-address-prefixes <ir-host-ip> --destination-port-ranges 22 3389
az network nsg rule create -g <rg> --nsg-name nsg-quarantine -n deny-all-in  --priority 4000 --direction Inbound  --access Deny --protocol '*' --source-address-prefixes '*' --destination-port-ranges '*'
az network nsg rule create -g <rg> --nsg-name nsg-quarantine -n deny-all-out --priority 4000 --direction Outbound --access Deny --protocol '*' --destination-address-prefixes '*' --destination-port-ranges '*'

az network nic update -g <rg> -n <nic> --network-security-group nsg-quarantine
```

The **subnet** NSG still applies; if it allows more, attach the quarantine NSG to an isolated subnet or move the NIC. If Defender for Endpoint is onboarded, its **Isolate device** action also cuts traffic inside the guest ([Defender XDR](../microsoft-365/defender.md)).

## 3. Preserve evidence

### Disk snapshots

```bash
for disk in $(az vm show -g <rg> -n <vm> --query "[storageProfile.osDisk.managedDisk.id, storageProfile.dataDisks[].managedDisk.id][]" -o tsv); do
  name=$(basename "$disk")
  az snapshot create -g <ir-rg> -n "ir-$(date -u +%Y%m%dT%H%MZ)-$name" --source "$disk" \
    --tags case=<case-id> collectedBy=<analyst> --network-access-policy DenyAll
done
```

Snapshot into a dedicated **IR resource group** (ideally a separate, locked-down subscription) with a `CanNotDelete` lock. To analyze, create a disk from the snapshot and attach it **read-only** to a forensic VM; never attach it to the original.

Export a hash-verifiable copy:

```bash
sas=$(az snapshot grant-access -g <ir-rg> -n <snapshot> --duration-in-seconds 3600 --access-level Read --query accessSas -o tsv)
azcopy copy "$sas" "https://<ir-storage>.blob.core.windows.net/evidence/<case-id>/<snapshot>.vhd"
az snapshot revoke-access -g <ir-rg> -n <snapshot>
```

### Memory

Collect memory **inside the guest** before shutdown ([Memory acquisition](../../tasks/forensics/memory-acquisition-analysis.md)). Run Command can launch a collector, but it runs as SYSTEM/root and writes to the evidence disk. Record that in your notes.

### Logs

Export `AzureActivity`, `SigninLogs`, `AuditLogs` and relevant resource logs for the full window ([Audit logging](audit-logging.md#6-export-for-an-investigation)). Raise workspace retention if the window is close to expiring.

## 4. Scope the intrusion

```kusto
// Everything the compromised principal touched
AzureActivity
| where TimeGenerated > ago(30d) and (Caller =~ "<upn>" or Caller == "<object-id>")
| summarize Ops = count(), First = min(TimeGenerated), Last = max(TimeGenerated)
    by OperationNameValue, ResourceGroup, ActivityStatusValue
| order by First asc
```

Check for persistence the attacker may have left: new role assignments, app credentials, automation runbooks, VM extensions and Run Commands, Logic Apps, new users or guests. See [Persistence & threat hunting](persistence-hunting.md).

## 5. Contain resources

| Resource | Action |
| :--- | :--- |
| Storage account | Rotate both keys, revoke user delegation keys, `--allow-shared-key-access false`, `--default-action Deny` ([Storage](storage.md#3-keys-and-sas-tokens)) |
| Key Vault | Rotate exposed secrets; disable old versions; review `SecretGet` callers ([Key Vault](keys-secrets.md#7-audit-secret-access)) |
| Crypto-mining / hijacked compute | Deallocate after evidence is taken; delete attacker-created resources; check quotas and provider registrations ([Azure resource hijacking](../../tasks/incident-response/azure-resource-hijacking.md)) |
| AKS | Rotate certs, disable local accounts, cordon nodes ([AKS](kubernetes.md#7-incident-actions-change)) |

## 6. Recover

- Rebuild VMs from known-good images; do not "clean" a compromised VM in place.
- Re-enable identities only after credentials are rotated and MFA/Conditional Access is confirmed.
- Add the detection that would have caught this sooner, and a lock or policy that would have blocked it.

## Related

- [Automated containment runbook](../../tasks/incident-response/automated-containment.md)
- [Microsoft 365 → Unified Audit Log](../microsoft-365/audit-log-investigation.md)
- [Concept: DFIR](../../fundamentals/concepts/digital-forensics.md)

## Sources

- [Azure forensics guidance (chain of custody for VM snapshots)](https://learn.microsoft.com/azure/architecture/example-scenario/forensics/)
- [Revoke user access in an emergency](https://learn.microsoft.com/entra/identity/users/users-revoke-access)
- [Microsoft incident response playbooks](https://learn.microsoft.com/security/operations/incident-response-playbooks)
