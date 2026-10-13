---
title: Google Cloud Persistence & Threat Hunting
platforms: [GCP]
languages: [Bash, Python]
tasks: [Threat Hunting, Incident Response, Investigation, Detection Engineering]
category: Persistence
tags: [gcp, persistence, threat hunting, service account keys, iam bindings, cloud functions, startup scripts, impersonation, mitre attack cloud]
aliases: [gcp persistence techniques, hunt new service account keys, gcp iam policy change query, gcp malicious cloud function, gcp startup script backdoor, gcp external principal granted role]
difficulty: advanced
verified: true
last_verified: 2026-10-12
---

# Google Cloud Persistence & Threat Hunting

Attackers with a foothold in Google Cloud keep access by **creating credentials** (SA keys, HMAC keys), **granting roles** to identities they control, or **deploying code** that runs as a privileged service account. All of these leave Admin Activity audit logs, which are always on.

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. All queries here are read-only.

## 1. Technique map

| Technique | MITRE ATT&CK | Audit `methodName` |
| :--- | :--- | :--- |
| New service-account key | T1098.001 Additional Cloud Credentials | `google.iam.admin.v1.CreateServiceAccountKey` |
| New HMAC key | T1098.001 | `CreateHmacKey` (`storage.googleapis.com`) |
| Role granted to outside identity | T1098.003 Additional Cloud Roles | `SetIamPolicy` |
| Self-grant of impersonation | T1098.003 | `SetIamPolicy` on a service account (`iam.serviceAccounts.setIamPolicy`) |
| New service account | T1136.003 Cloud Account | `google.iam.admin.v1.CreateServiceAccount` |
| Function / Cloud Run running as privileged SA | T1525 / T1648 Serverless Execution | `google.cloud.functions.v2.FunctionService.CreateFunction`, `google.cloud.run.v2.Services.CreateService` |
| SSH key or startup script in metadata | T1098.004 SSH Authorized Keys / T1037 | `v1.compute.projects.setCommonInstanceMetadata`, `v1.compute.instances.setMetadata` |
| Workload Identity Federation pool for attacker IdP | T1484.002 Trust Modification | `CreateWorkloadIdentityPoolProvider` |
| Log sink deleted / exclusion added | T1562.008 Disable Cloud Logs | `google.logging.v2.ConfigServiceV2.DeleteSink`, `CreateExclusion` |

## 2. Hunts

Run each over 30–90 days with `--organization=<ORG_ID>` against an org-level log bucket, or in BigQuery.

```bash
# H1: service-account keys created (who, for which SA, from where)
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' --freshness=30d \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.request.name, protoPayload.requestMetadata.callerIp)"

# H2: IAM grants to principals outside your domain
gcloud logging read 'protoPayload.methodName="SetIamPolicy"
  AND protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
  AND NOT protoPayload.serviceData.policyDelta.bindingDeltas.member:"@example.com"' --freshness=30d

# H3: someone granted themselves token-creator or SA-user
gcloud logging read 'protoPayload.methodName:"SetIamPolicy"
  AND protoPayload.serviceData.policyDelta.bindingDeltas.role=("roles/iam.serviceAccountTokenCreator" OR "roles/iam.serviceAccountUser" OR "roles/owner")' --freshness=30d

# H4: functions and Cloud Run services created or updated
gcloud logging read 'protoPayload.methodName:("CreateFunction" OR "UpdateFunction" OR "CreateService" OR "ReplaceService")
  AND protoPayload.serviceName:("cloudfunctions.googleapis.com" OR "run.googleapis.com")' --freshness=30d

# H5: project or instance metadata changes (ssh-keys, startup-script)
gcloud logging read 'protoPayload.methodName:("setCommonInstanceMetadata" OR "instances.setMetadata")' --freshness=30d

# H6: key used from an IP never seen before (export and compare per key)
gcloud logging read 'protoPayload.authenticationInfo.serviceAccountKeyName:*' --freshness=30d --format=json \
  | jq -r '.[] | [.protoPayload.authenticationInfo.serviceAccountKeyName, .protoPayload.requestMetadata.callerIp] | @tsv' | sort | uniq -c | sort -n | head
```

Policy changes made with `setIamPolicy` record a `policyDelta` (only what changed); read it rather than diffing whole policies.

## 3. Point-in-time sweep (no logs needed)

```bash
ORG=<ORG_ID>
# user-managed SA keys everywhere
gcloud asset search-all-resources --scope=organizations/$ORG --asset-types=iam.googleapis.com/ServiceAccountKey \
  --query="keyType=USER_MANAGED" --format="table(name, createTime)"
# bindings to gmail.com or other external domains, and public grants
gcloud asset search-all-iam-policies --scope=organizations/$ORG --query="policy:(gmail.com OR allUsers OR allAuthenticatedUsers)"
# functions and services and the identity they run as
gcloud functions list --format="table(name, environment, serviceConfig.serviceAccountEmail, updateTime)"
gcloud run services list --format="table(metadata.name, region, spec.template.spec.serviceAccountName, metadata.creationTimestamp)"
# workload identity pools (trust to external IdPs)
gcloud iam workload-identity-pools list --location=global
# project metadata that creates users or runs code
gcloud compute project-info describe --format="flattened(commonInstanceMetadata.items[].key)"
```

## 4. Python: flag IAM members outside allowed domains

```python
import json, subprocess

ALLOWED = ("@example.com", ".iam.gserviceaccount.com", "@cloudservices.gserviceaccount.com")
ORG = "123456789012"
out = subprocess.run(["gcloud", "asset", "search-all-iam-policies", f"--scope=organizations/{ORG}",
                      "--format=json"], capture_output=True, text=True, check=True).stdout
for res in json.loads(out):
    for b in res.get("policy", {}).get("bindings", []):
        for m in b.get("members", []):
            email = m.split(":", 1)[-1]
            if m.startswith(("domain:", "allUsers", "allAuthenticatedUsers")) or not email.endswith(ALLOWED):
                if not email.endswith(".gserviceaccount.com"):   # Google service agents
                    print(res["resource"], b["role"], m)
```

Review results by hand: service agents of other Google services and partner integrations are legitimate external members.

## Related

- [Incident response](incident-response.md)
- [Identity & access](identity-access.md)
- [Task: hypothesis-driven hunting](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md)

## Sources

- [MITRE ATT&CK: Cloud matrix (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
- [IAM audit logging](https://cloud.google.com/iam/docs/audit-logging)
- [Event Threat Detection rules](https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview#rules)
- [Cloud Asset Inventory: search IAM policies](https://cloud.google.com/asset-inventory/docs/searching-iam-policies)
