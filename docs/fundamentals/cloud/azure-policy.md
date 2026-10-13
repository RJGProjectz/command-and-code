---
title: Fundamentals — Azure Policy & Governance Baselines
type: entry
platforms:
  - Azure
languages:
  - PowerShell
tasks:
  - Assurance
  - Hardening
verified: true
last_verified: 2026-10-12
difficulty: intermediate
tags:
  - azure
  - azure-policy
  - governance
  - compliance
---

# Fundamentals — Azure Policy & Governance Baselines

Azure Policy enforces organizational standards and assesses cloud resource compliance at scale across subscriptions and management groups.

**How it fits:** RBAC controls *who* can act; Azure Policy controls *what* the resulting resources may look like, whoever creates them. A policy **definition** (rule + effect) is grouped into an **initiative** (policy set) and **assigned** to a scope (management group, subscription or resource group). Assignments inherit downwards; exemptions carve out exceptions with an expiry date.

## 1. Effect Types

| Effect | Execution Stage | Action |
| :--- | :--- | :--- |
| `Deny` | During create/update | Blocks the request before the resource is created or changed |
| `DenyAction` | During delete | Blocks a delete operation (for example protect critical resources) |
| `Audit` | Evaluation | Marks the resource non-compliant and writes a warning event to the Activity Log |
| `AuditIfNotExists` | After create/update | Non-compliant when a related resource is missing (e.g. no diagnostic setting) |
| `Append` | During create/update | Adds fields to the request (e.g. an IP rule) |
| `Modify` | During create/update, and remediation tasks | Adds, replaces or removes tags and modifiable properties (e.g. minimum TLS version) |
| `DeployIfNotExists` | After a successful create/update, and remediation tasks | Deploys a missing related resource (e.g. Azure Monitor Agent, diagnostic settings, Defender plans) |
| `Manual` | Attestation | A person records compliance for controls that cannot be evaluated automatically |
| `Disabled` | — | Turns the rule off (useful as a parameter value) |

`Modify` and `DeployIfNotExists` assignments use a **managed identity** to make changes; that identity needs the roles listed in the definition. Existing resources are fixed only when you create a **remediation task**.

## 2. Security baseline to start with

- **Microsoft cloud security benchmark** initiative: assigned by default with Microsoft Defender for Cloud; the source of your Secure Score recommendations.
- **Allowed locations** (`Deny`): keeps data in approved regions.
- **Deny public network access** for storage accounts, key vaults and databases where private endpoints are the standard.
- **Diagnostic settings to Log Analytics** (`DeployIfNotExists`): keeps resource logs for investigations.
- **Require tags** such as `owner` and `environment` (`Modify` to inherit from the resource group).

Roll out new `Deny` policies as `Audit` first, review the non-compliant list, then switch the effect.

## 3. Check compliance

```bash
# Assignments at the current subscription
az policy assignment list --query "[].{name:name, displayName:displayName, scope:scope}" -o table

# Non-compliant resources (latest evaluation)
az policy state list --filter "complianceState eq 'NonCompliant'" \
    --query "[].{resource:resourceId, policy:policyDefinitionName}" -o table

# Trigger a fresh evaluation (otherwise every 24 hours, and on change)
az policy state trigger-scan --resource-group <resource-group>
```

## 4. Security angle

Policy changes are themselves sensitive: deleting a `Deny` assignment or adding a broad exemption quietly removes a guardrail. Watch the Activity Log for `Microsoft.Authorization/policyAssignments/delete` and `Microsoft.Authorization/policyExemptions/write`, and limit `Resource Policy Contributor` to the platform team.

## Related

- [Azure platform overview](../../platforms/azure/index.md)
- [Azure NSG compliance check](../../tasks/assurance/azure-nsg-compliance.md)

## Sources

- [Microsoft Learn — Azure Policy overview](https://learn.microsoft.com/azure/governance/policy/overview)
- [Microsoft Learn — Azure Policy effects](https://learn.microsoft.com/azure/governance/policy/concepts/effect-basics)
- [Microsoft Learn — Remediate non-compliant resources](https://learn.microsoft.com/azure/governance/policy/how-to/remediate-resources)
- [Microsoft Learn — az policy state](https://learn.microsoft.com/cli/azure/policy/state)
