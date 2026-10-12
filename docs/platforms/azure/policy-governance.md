---
title: Azure Policy, Locks & Governance
platforms: [Azure]
languages: [Bash, PowerShell, KQL]
tasks: [Hardening, Assurance, Administration, Governance]
category: Governance
tags: [azure, azure policy, initiative, compliance, deny, deployifnotexists, resource locks, tags, landing zone]
aliases: [azure policy compliance state, azure deny policy, assign azure policy cli, azure resource lock, cannotdelete lock, allowed locations policy, azure policy remediation]
difficulty: intermediate
verified: false
---

# Azure Policy, Locks & Governance

**Azure Policy** evaluates every resource against rules and can **audit**, **deny**, **modify** or **deploy** configuration. **Resource locks** stop deletion or change, even by Owners. Assign both at **management-group** scope so new subscriptions inherit them ([Resource hierarchy](resource-hierarchy.md)).

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Microsoft documentation and not yet lab-tested in this repo. Commands that change state are marked **change**. Test `Deny` policies in `Audit` (or `DoNotEnforce`) mode first; they block deployments immediately.

## 1. Effects

| Effect | What happens | Use for |
| :--- | :--- | :--- |
| `Audit` / `AuditIfNotExists` | Marks non-compliant, nothing blocked | Discovery |
| `Deny` / `DenyAction` | Blocks the create/update (or delete) request | Hard guardrails: allowed regions, no public IPs |
| `Modify` | Adds or changes properties (tags, settings) on create/update | Tag inheritance, TLS settings |
| `DeployIfNotExists` | Deploys a companion resource via a managed identity | Diagnostic settings, agents, Defender plans |
| `Disabled` | Off | Exemption by parameter |

## 2. See what is assigned and how compliant you are

```bash
az policy assignment list --disable-scope-strict-match --query "[].{name:displayName, scope:scope, mode:enforcementMode}" -o table
az policy state summarize --query "results.{nonCompliantResources:nonCompliantResources, nonCompliantPolicies:nonCompliantPolicies}"
az policy state list --filter "complianceState eq 'NonCompliant'" \
  --query "[].{policy:policyDefinitionName, resource:resourceId}" --top 50 -o table
```

```kusto
// Resource Graph: non-compliant resources by policy across all subscriptions
policyresources
| where type == "microsoft.policyinsights/policystates"
| where properties.complianceState == "NonCompliant"
| summarize Resources = dcount(tostring(properties.resourceId)) by Policy = tostring(properties.policyDefinitionName),
            Assignment = tostring(properties.policyAssignmentName)
| order by Resources desc
```

Trigger a fresh evaluation (results take several minutes): `az policy state trigger-scan --resource-group <rg>`.

## 3. Resource locks

| Lock | Blocks |
| :--- | :--- |
| `CanNotDelete` | Delete; changes still allowed |
| `ReadOnly` | Delete and change. Also blocks some *read* operations that use POST, such as listing storage keys. |

```bash
az lock list -o table
az lock create --name lock-no-delete --lock-type CanNotDelete --resource-group <rg>             # change
az lock create --name lock-law --lock-type CanNotDelete --resource <law-id>                   # change
az lock delete --name lock-no-delete --resource-group <rg>                                    # change
```

Put `CanNotDelete` on log workspaces, backup vaults, Key Vaults and hub networking. Deleting a lock is logged as `MICROSOFT.AUTHORIZATION/LOCKS/DELETE`; alert on it.

## 4. Assign a built-in policy (change)

```bash
# Find the definition
az policy definition list --query "[?contains(displayName,'Allowed locations')].{name:name, display:displayName}" -o table

# Allowed locations at a management group
az policy assignment create --name allowed-locations \
  --policy e56962a6-4747-49cd-b67b-bf8b01975c4c \
  --scope /providers/Microsoft.Management/managementGroups/<mg> \
  --params '{"listOfAllowedLocations":{"value":["canadacentral","canadaeast"]}}'

# Start in audit-only mode for an existing assignment
az policy assignment update --name allowed-locations --scope <scope> --enforcement-mode DoNotEnforce
```

High-value built-in policies to start with:

- Allowed locations; Allowed virtual machine SKUs
- Storage accounts should prevent shared key access / disable public network access
- Key vaults should have deletion protection enabled
- Configure diagnostic settings to Log Analytics (allLogs category group) for each resource type
- Management ports should be closed on your virtual machines
- Require a tag and its value on resources / Inherit a tag from the resource group (`Modify`)

## 5. Remediate DeployIfNotExists and Modify (change)

Existing resources are not fixed automatically; create a remediation task.

```bash
az policy remediation create --name fix-diag --policy-assignment <assignment-id> --resource-discovery-mode ReEvaluateCompliance
az policy remediation list -o table
```

The assignment's managed identity needs the roles listed in the policy's `roleDefinitionIds`.

## 6. Exemptions

```bash
az policy exemption list -o table
az policy exemption create --name exempt-legacy-app --policy-assignment <assignment-id> \
  --exemption-category Waiver --expires-on 2027-03-31 --resource-group <rg> --description "Ticket CHG-1234"   # change
```

Every exemption should have an expiry date and a ticket. Review the list monthly.

## 7. Governance at scale

- **Azure Landing Zones** (Cloud Adoption Framework) ship a management-group hierarchy and policy set; start there rather than writing your own.
- Store policy definitions and assignments as code (Bicep/Terraform), deploy through a pipeline, and review changes like application code.
- Watch for drift: `MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/DELETE` and `.../POLICYEXEMPTIONS/WRITE` in [Activity Log](audit-logging.md).

## Related

- [Security posture](security-posture.md)
- [Concept: GRC](../../fundamentals/grc/regulatory-frameworks.md)
- [Azure security baseline](../../tasks/hardening/cloud-azure-security-baseline.md)

## Sources

- [Azure Policy overview](https://learn.microsoft.com/azure/governance/policy/overview)
- [Policy effects](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics)
- [Lock resources](https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources)
