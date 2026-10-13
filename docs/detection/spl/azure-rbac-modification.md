---
title: Splunk Detection — Suspicious Azure RBAC Modification
type: entry
platforms:
  - Azure
  - Splunk
languages:
  - SPL
tasks:
  - Detection Engineering
  - Threat Hunting
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - splunk
  - azure
  - rbac
  - privilege-escalation
---

# Splunk Detection — Suspicious Azure RBAC Modification

Detects unauthorized assignment of high-privilege roles (e.g. `Owner`, `User Access Administrator`) to user accounts or service principals in Azure subscriptions.

## Why it matters

A role assignment at subscription or management-group scope is the most direct way to gain or keep control of Azure resources. `Owner` and `User Access Administrator` can grant roles to anyone, so one unexpected assignment is enough for an attacker to persist after the original credential is revoked.

- **Log Source**: Azure Activity Log (category `Administrative`), sent to Splunk by the Splunk Add-on for Microsoft Cloud Services or through Event Hub
- **ATT&CK Technique**: [T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/) · [T1078.004 - Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)

## Detection Logic

The role being granted is inside `properties.requestbody`, which is stored as a JSON **string**, so extract the role-definition GUID with `rex` instead of a nested `spath` path:

```spl
index=azure_activity operationName="Microsoft.Authorization/roleAssignments/write"
| rex field=_raw "roleDefinitions/(?<role_id>[0-9a-fA-F-]{36})"
| eval role_name=case(
    role_id="8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "Owner",
    role_id="18d7d88d-d35e-4fb5-a5f3-7702510d2926", "User Access Administrator",
    role_id="b24988ac-6180-42a0-ab88-20f7382dd24c", "Contributor",
    true(), "other")
| where role_name!="other"
| table _time, caller, role_name, role_id, resourceId, resultType
```

Searches are case-insensitive for field values, so the upper-case `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` used by diagnostic-settings exports also matches. Each write logs a `Start` and a `Success` (or `Failure`) event; keep both while tuning, then filter on `resultType=Success`.

The GUIDs are Azure built-in role IDs and are the same in every tenant. Custom roles that include `Microsoft.Authorization/roleAssignments/write` are just as dangerous; add their IDs to a lookup.

## Tuning and false positives

- Expected callers: your IaC pipeline service principal, Privileged Identity Management (PIM) activations, and named platform admins. Put them in a lookup and exclude them by `caller`.
- PIM activations appear as assignments made by the PIM service; correlate with the Entra audit log (`Add member to role completed (PIM activation)`).
- Alert on every assignment at **subscription or management-group scope** (`resourceId` without `/resourceGroups/`) regardless of caller.

## Respond

1. Who is the new principal (user, group, service principal, managed identity) and who granted it? Check the caller's sign-in logs for that time.
2. List all current assignments for that principal:
   `az role assignment list --assignee <object-id> --all --output table`
3. If unapproved: remove the assignment, revoke the caller's sessions, and review everything the new principal did since the grant.
   → [Compromised Service Principal](../../tasks/incident-response/compromised-service-principal.md) · [Azure Resource Hijacking](../../tasks/incident-response/azure-resource-hijacking.md)

## Related

- [Azure platform overview](../../platforms/azure/index.md)
- [Cloud Identity Persistence Hunting](../../tasks/threat-hunting/cloud-identity-persistence-hunting.md)

## Sources

- [Microsoft Learn — Azure built-in roles (IDs)](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles)
- [Microsoft Learn — Azure Activity Log event schema](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log-schema)
- [MITRE ATT&CK T1098](https://attack.mitre.org/techniques/T1098/)
