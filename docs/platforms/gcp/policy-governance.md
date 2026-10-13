---
title: Google Cloud Organization Policy & Governance
platforms: [GCP]
languages: [Bash]
tasks: [Hardening, Assurance, Administration, Governance]
category: Governance
tags: [gcp, organization policy, org policy constraints, custom constraints, deny policies, iam conditions, policy simulator, liens, cis benchmark]
aliases: [gcloud org-policies list, gcp disable service account key creation, gcp restrict public ip, gcp domain restricted sharing, gcp custom org policy constraint, gcp project lien]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Cloud Organization Policy & Governance

Google Cloud has three guardrails above ordinary IAM grants:

| Guardrail | Controls | AWS equivalent |
| :--- | :--- | :--- |
| **Organization Policy** | **What** can be configured (no external IPs, no SA keys, allowed regions) | Config rules + some SCPs |
| **IAM deny policies** | **Who** can never use certain permissions, whatever their roles | SCPs |
| **VPC Service Controls** | Where data can flow ([Networking](networking.md#5-keep-traffic-private)) | Data perimeters |

Org Policies are set at organization, folder or project and inherited; a child can override unless the parent forbids it.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**. Test policies on one folder or with **dry run** before enforcing org-wide.

## 1. Read current policies

```bash
gcloud org-policies list --organization=<ORG_ID>
gcloud org-policies list --project=<PROJECT_ID> --show-unset | head -40
gcloud org-policies describe iam.disableServiceAccountKeyCreation --project=<PROJECT_ID> --effective
gcloud org-policies describe compute.vmExternalIpAccess --folder=<FOLDER_ID>
```

`--effective` shows the result after inheritance, which is what actually applies.

## 2. Security constraints to set

| Constraint | Effect |
| :--- | :--- |
| `iam.disableServiceAccountKeyCreation` | No downloadable SA keys |
| `iam.allowedPolicyMemberDomains` | Only your Cloud Identity customer IDs can be granted roles (blocks `allUsers`) |
| `iam.automaticIamGrantsForDefaultServiceAccounts` | Default SAs do not get Editor |
| `storage.publicAccessPrevention` | No public buckets |
| `storage.uniformBucketLevelAccess` | No object ACLs |
| `compute.vmExternalIpAccess` | Allow-list VMs that may have external IPs |
| `compute.requireOsLogin`, `compute.disableSerialPortAccess` | SSH through identity only |
| `compute.skipDefaultNetworkCreation` | No permissive `default` VPC in new projects |
| `gcp.resourceLocations` | Restrict regions (data residency) |
| `sql.restrictPublicIp` | No public Cloud SQL |

```yaml
# policy.yaml
name: organizations/<ORG_ID>/policies/iam.disableServiceAccountKeyCreation
spec:
  rules:
    - enforce: true
```

```bash
gcloud org-policies set-policy policy.yaml          # change
gcloud resource-manager org-policies enable-enforce compute.requireOsLogin --organization=<ORG_ID>   # change (older command)
```

## 3. Dry run and custom constraints

```yaml
# dry run: violations are logged, nothing is blocked
name: folders/<FOLDER_ID>/policies/compute.vmExternalIpAccess
dryRunSpec:
  rules:
    - denyAll: true
```

```yaml
# custom constraint: GKE clusters must have private nodes
name: organizations/<ORG_ID>/customConstraints/custom.gkeRequirePrivateNodes
resourceTypes: [container.googleapis.com/Cluster]
methodTypes: [CREATE, UPDATE]
condition: "resource.privateClusterConfig.enablePrivateNodes == true"
actionType: ALLOW
displayName: Require private GKE nodes
```

```bash
gcloud org-policies set-custom-constraint custom-constraint.yaml   # change; then enforce it with a policy
```

Dry-run violations appear in the **Policy Denied** audit log.

## 4. IAM deny policies

```json
{
  "displayName": "No one outside the security group changes audit config",
  "rules": [{
    "denyRule": {
      "deniedPrincipals": ["principalSet://goog/public:all"],
      "exceptionPrincipals": ["principalSet://goog/group/sec-admins@example.com"],
      "deniedPermissions": ["logging.googleapis.com/sinks.delete", "logging.googleapis.com/sinks.update"]
    }
  }]
}
```

```bash
gcloud iam policies create deny-log-tamper --attachment-point=cloudresourcemanager.googleapis.com%2Forganizations%2F<ORG_ID> \
  --kind=denypolicies --policy-file=deny.json     # change
gcloud iam policies list --attachment-point=cloudresourcemanager.googleapis.com%2Forganizations%2F<ORG_ID> --kind=denypolicies
```

## 5. Protect projects from deletion

```bash
gcloud alpha resource-manager liens create --project=<PROJECT_ID> \
  --restrictions=resourcemanager.projects.delete --reason="Log archive project"   # change
gcloud alpha resource-manager liens list --project=<PROJECT_ID>
```

Deleted projects can be restored for 30 days with `gcloud projects undelete`.

## 6. Check compliance

- SCC Premium compliance reports map findings to CIS Google Cloud Foundations Benchmark, PCI DSS and NIST ([Security posture](security-posture.md)).
- **Policy Simulator** previews the effect of an IAM or Org Policy change before you apply it.
- Audit org-policy changes: `gcloud logging read 'protoPayload.serviceName="orgpolicy.googleapis.com"' --organization=<ORG_ID> --freshness=30d`.

## Related

- [Resource hierarchy](resource-hierarchy.md)
- [Identity & access](identity-access.md#7-baseline)
- [GRC: regulatory frameworks](../../fundamentals/grc/regulatory-frameworks.md)

## Sources

- [Organization Policy Service overview](https://cloud.google.com/resource-manager/docs/organization-policy/overview)
- [Organization policy constraints list](https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints)
- [Custom constraints](https://cloud.google.com/resource-manager/docs/organization-policy/creating-managing-custom-constraints)
- [IAM deny policies](https://cloud.google.com/iam/docs/deny-overview)
