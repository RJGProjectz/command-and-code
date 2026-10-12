---
title: Azure Identity & Access (RBAC, PIM, Managed Identities)
platforms: [Azure, Entra ID]
languages: [Bash, PowerShell, KQL]
tasks: [Administration, Hardening, Investigation, Assurance]
category: Identity
tags: [azure, rbac, role assignment, pim, managed identity, service principal, owner, contributor]
aliases: [azure role assignments, who has owner on subscription, azure rbac audit, azure pim activation, managed identity permissions, user access administrator]
difficulty: intermediate
verified: false
---

# Azure Identity & Access (RBAC, PIM, Managed Identities)

Azure RBAC decides what an identity can do to resources. A **role assignment** = security principal (user, group, service principal, managed identity) + **role definition** + **scope** (management group, subscription, resource group, resource). Entra ID roles (Global Administrator, etc.) are a separate system covered under [Entra ID](../microsoft-365/entra.md#privileged-role-members).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. The roles that matter

| Role | Why it matters |
| :--- | :--- |
| **Owner** | Full control including granting access. Equals takeover of the scope. |
| **User Access Administrator** | Can grant any role, including Owner, to anyone. |
| **Role Based Access Control Administrator** | Can assign roles; can be constrained with conditions. |
| **Contributor** | Full control of resources but cannot grant access. Can still run code on VMs (Run Command) and read secrets from many services. |
| **Virtual Machine Contributor** | Run Command and extensions = code execution as SYSTEM/root on VMs. |
| **Key Vault Secrets User / Officer** | Read or manage secrets ([Keys & secrets](keys-secrets.md)). |

A Global Administrator in Entra ID can **elevate** to User Access Administrator at the root scope (`/`) for all subscriptions. Check for it (section 4).

## 2. List role assignments

```bash
# Everything at and below the current subscription, including inherited ones
az role assignment list --all --include-inherited \
  --query "[].{principal:principalName, type:principalType, role:roleDefinitionName, scope:scope}" -o table

# Only privileged roles
az role assignment list --all --include-inherited \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator'].{p:principalName, t:principalType, s:scope}" -o table

# What one principal has
az role assignment list --assignee <upn-or-object-id> --all --include-inherited -o table
```

```powershell
Get-AzRoleAssignment |
  Where-Object RoleDefinitionName -in 'Owner','User Access Administrator','Role Based Access Control Administrator' |
  Select-Object DisplayName, SignInName, ObjectType, RoleDefinitionName, Scope
```

Across many subscriptions, query Resource Graph instead:

```kusto
authorizationresources
| where type == "microsoft.authorization/roleassignments"
| extend roleId = tostring(properties.roleDefinitionId), principalId = tostring(properties.principalId),
         principalType = tostring(properties.principalType), scope = tostring(properties.scope)
| join kind=leftouter (authorizationresources
    | where type == "microsoft.authorization/roledefinitions"
    | project roleId = id, roleName = tostring(properties.roleName)) on roleId
| where roleName in ("Owner", "User Access Administrator")
| project principalId, principalType, roleName, scope
```

## 3. Custom roles

Custom roles with wildcards (`*`) or `Microsoft.Authorization/roleAssignments/write` are privilege-escalation paths.

```bash
az role definition list --custom-role-only true \
  --query "[].{name:roleName, actions:permissions[0].actions, scopes:assignableScopes}" -o json
```

## 4. Root-scope elevation

```bash
az role assignment list --scope "/" --role "User Access Administrator" -o table
```

Remove it as soon as the task is done (**change**):

```bash
az role assignment delete --scope "/" --role "User Access Administrator" --assignee <upn>
```

The elevation itself is logged in the Entra ID audit log as *"User has elevated their access to User Access Administrator for their Azure Resources"*.

## 5. Managed identities

Managed identities have no password to steal, but anything that runs on the resource can get a token for them. Audit what each identity can reach.

```bash
# System-assigned identities on VMs
az vm list --query "[?identity].{vm:name, type:identity.type, principalId:identity.principalId}" -o table

# User-assigned identities
az identity list --query "[].{name:name, rg:resourceGroup, principalId:principalId, clientId:clientId}" -o table

# What the identity can do
az role assignment list --assignee <principal-id> --all -o table
```

## 6. Privileged Identity Management (PIM)

With PIM, privileged Azure roles should be **eligible**, not active. Active permanent Owner assignments outside break-glass accounts are a finding.

```powershell
# Eligible and active schedule instances at a subscription scope
$scope = "/subscriptions/<sub-id>"
Get-AzRoleEligibilityScheduleInstance -Scope $scope | Select-Object PrincipalDisplayName, RoleDefinitionDisplayName, EndDateTime
Get-AzRoleAssignmentScheduleInstance -Scope $scope | Where-Object AssignmentType -eq 'Assigned' |
  Select-Object PrincipalDisplayName, RoleDefinitionDisplayName, EndDateTime
```

## 7. Grant and remove access (change)

```bash
az role assignment create --assignee <object-id> --role "Reader" --scope /subscriptions/<sub-id>/resourceGroups/<rg>
az role assignment delete --assignee <object-id> --role "Owner" --scope /subscriptions/<sub-id>
```

Assign roles to **groups**, at the **narrowest scope**, with the **least-privileged built-in role** that does the job.

## 8. Detect new privileged assignments

Role assignments are written to the Activity Log (`Microsoft.Authorization/roleAssignments/write`). In Log Analytics:

```kusto
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| extend roleDef = tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties.RoleDefinitionId)
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, roleDef
| order by TimeGenerated desc
```

Map `roleDef` GUIDs to names: Owner = `8e3af657-a8ff-443c-a75c-2fe8c4bcb635`, Contributor = `b24988ac-6180-42a0-ab88-20f7382dd24c`, User Access Administrator = `18d7d88d-d35e-4fb5-a5c3-7773c20a72d9`.

## Related

- [Persistence & threat hunting](persistence-hunting.md)
- [Concept: access-control models](../../fundamentals/concepts/access-control-models.md)
- [Concept: IAM and PAM](../../fundamentals/concepts/identity-access-management.md)

## Sources

- [Azure built-in roles](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles)
- [Elevate access for a Global Administrator](https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin)
- [PIM for Azure resources](https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles)
