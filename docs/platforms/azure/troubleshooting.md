---
title: Azure Troubleshooting
platforms: [Azure]
languages: [Bash, PowerShell]
tasks: [Troubleshooting, Administration]
category: Troubleshooting
tags: [azure, troubleshooting, authorizationfailed, quota, resource provider, nsg, deployment errors, vm agent]
aliases: [azure authorizationfailed, azure deployment failed, azure quota exceeded, missingsubscriptionregistration, cannot rdp azure vm, azure vm agent not ready, requestdisallowedbypolicy]
difficulty: intermediate
verified: false
---

# Azure Troubleshooting

Most Azure failures fall into five groups: **who you are**, **what you may do**, **what the platform allows** (policy, quota, provider), **network path**, and **inside the guest**. Read the error code before anything else; it names the group.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Authentication and authorization errors

| Error | Meaning | Check |
| :--- | :--- | :--- |
| `AADSTS50076` / `AADSTS50079` | MFA required | Sign in interactively, or use a service principal / managed identity |
| `AADSTS53003` | Blocked by Conditional Access | Entra sign-in log → Conditional Access tab ([Conditional Access](../microsoft-365/conditional-access.md#why-was-this-sign-in-blocked)) |
| `AADSTS700016` | App ID not found in that tenant | Wrong `--tenant`, or the app is single-tenant |
| `AADSTS7000222` | Client secret expired | `az ad app credential list --id <app-id>` |
| `AuthorizationFailed` | Signed in, but no role grants the action at that scope | Section 2 |
| `LinkedAuthorizationFailed` | Missing permission on a *linked* resource (subnet, Key Vault, identity) | The message names the second resource |

```bash
az account show --query "{tenant:tenantId, sub:id, user:user.name}"   # right tenant and subscription?
az account get-access-token --query expiresOn -o tsv                  # still valid?
```

## 2. "AuthorizationFailed": which permission is missing?

The error names the action (for example `Microsoft.Compute/virtualMachines/write`) and the scope.

```bash
az role assignment list --assignee <upn-or-id> --all --include-inherited -o table
az role definition list --name "<role>" --query "[].permissions[].{actions:actions, notActions:notActions}"
```

- Role assignments can take up to **10 minutes** to apply; sign out and in again (`az account clear && az login`) to refresh cached tokens and group membership.
- A **deny assignment** (from managed applications or Deployment Stacks) overrides any allow, and `az role assignment list` does not show it. Use the portal **Access control (IAM) → Deny assignments** tab.
- Data-plane operations (blobs, secrets) need **data** roles; Owner alone does not read blob data when shared key is disabled.

## 3. Cannot reach a VM

1. VM running, agent ready? `az vm get-instance-view -g <rg> -n <vm> --query "instanceView.{power:statuses[1].code, agent:vmAgent.statuses[0].displayStatus}"`
2. Which rule blocks it? `az network watcher test-ip-flow ...` ([Networking](networking.md#4-network-watcher-test-a-flow))
3. Effective NSG and routes on the NIC: `az network nic list-effective-nsg` / `show-effective-route-table`
4. Is there a public IP at all, or do you need Bastion / VPN?
5. Inside the guest: firewall, RDP/SSH service, disk full. Use **serial console** or **boot diagnostics** ([Compute](compute.md#6-console-access-without-the-network)).

Reset RDP configuration or SSH (**change**):

```bash
az vm user reset-ssh -g <rg> -n <vm>
az vm extension set -g <rg> --vm-name <vm> --name VMAccessAgent --publisher Microsoft.Compute --version 2.4 --settings '{}'   # Windows: resets RDP config
```

## 4. Deployment and platform errors

| Error code | Cause | Fix |
| :--- | :--- | :--- |
| `MissingSubscriptionRegistration` | Resource provider not registered | `az provider register -n Microsoft.<Namespace>` (**change**) |
| `RequestDisallowedByPolicy` | An Azure Policy `Deny` blocked it | The error names the assignment; see [Policy](policy-governance.md#2-see-what-is-assigned-and-how-compliant-you-are) or request an exemption |
| `ScopeLocked` | A resource lock | `az lock list` ([Locks](policy-governance.md#3-resource-locks)) |
| `OperationNotAllowed` / `QuotaExceeded` | vCPU or other quota | `az vm list-usage -l <region> -o table`; request an increase |
| `SkuNotAvailable` | Size not offered in that region/zone for your subscription | `az vm list-skus -l <region> --size Standard_D --query "[?restrictions]"` |
| `Conflict` / `AnotherOperationInProgress` | Another operation is still running on the resource | Wait, then retry |
| `InvalidTemplateDeployment` | Template validation failed | `az deployment group show -g <rg> -n <deployment> --query properties.error` |

```bash
# Last failed deployments and their errors
az deployment group list -g <rg> --query "[?properties.provisioningState=='Failed'].{name:name, time:properties.timestamp}" -o table
az deployment operation group list -g <rg> -n <deployment> --query "[?properties.provisioningState=='Failed'].properties.statusMessage"
```

## 5. CLI and module problems

```bash
az --version                     # outdated CLI is a common cause of "unrecognized arguments"
az <command> --debug 2>&1 | less # shows the HTTP request, URL and full error body
az config set core.only_show_errors=true
```

```powershell
Get-Module Az.* -ListAvailable | Group-Object Name | Where-Object Count -gt 1   # duplicate versions loaded
$DebugPreference = 'Continue'   # Az cmdlets print HTTP traffic
```

Corporate TLS inspection breaks the CLI with `CERTIFICATE_VERIFY_FAILED`; set `REQUESTS_CA_BUNDLE` to a bundle that includes the proxy CA rather than disabling verification.

## 6. Where to look next

- **Activity Log** for failed operations and their error text: `az monitor activity-log list --status Failed --offset 24h` ([Audit logging](audit-logging.md)).
- **Resource Health** (portal blade on each resource) for platform-side faults on one VM or service.
- **Service Health** for regional outages before you debug your own configuration.

## Related

- [Windows troubleshooting](../windows/troubleshooting.md) · [Linux troubleshooting](../linux/troubleshooting.md) inside the guest
- [CLI & authentication](cli-authentication.md)
- [Troubleshooting tasks](../../tasks/troubleshooting/index.md)

## Sources

- [Troubleshoot common Azure deployment errors](https://learn.microsoft.com/azure/azure-resource-manager/troubleshooting/common-deployment-errors)
- [Troubleshoot Azure RBAC](https://learn.microsoft.com/azure/role-based-access-control/troubleshooting)
- [Microsoft Entra authentication error codes](https://learn.microsoft.com/entra/identity-platform/reference-error-codes)
