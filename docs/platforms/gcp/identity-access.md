---
title: Google Cloud IAM (Identity & Access)
platforms: [GCP]
languages: [Bash, Python]
tasks: [Administration, Hardening, Investigation, Incident Response]
category: Identity
tags: [gcp, cloud iam, service accounts, service account keys, roles, iam conditions, policy analyzer, iam recommender, deny policies]
aliases: [gcloud projects get-iam-policy, gcp list service account keys, gcp who has owner role, gcloud iam roles describe, gcp policy analyzer, gcp unused permissions]
difficulty: intermediate
verified: false
---

# Google Cloud IAM (Identity & Access)

An IAM **allow policy** on a resource binds **principals** (users, groups, service accounts, `domain:`, `allUsers`) to **roles** (bundles of permissions). Policies inherit down the hierarchy and **add up**; only **deny policies** subtract. Users and groups live in Cloud Identity / Google Workspace; **service accounts** are the identities of workloads.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Read a policy

```bash
gcloud projects get-iam-policy <PROJECT_ID> --format=json > iam.json
gcloud projects get-iam-policy <PROJECT_ID> --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members, bindings.condition.title)"
gcloud resource-manager folders get-iam-policy <FOLDER_ID>
gcloud organizations get-iam-policy <ORG_ID>
```

A project policy alone is incomplete: also read the folders and organization above it ([hierarchy](resource-hierarchy.md#1-map-the-tree)), or use [Policy Analyzer](#4-policy-analyzer).

## 2. Risky roles

| Role | Why it matters |
| :--- | :--- |
| `roles/owner`, `roles/editor` | Basic roles; editor can modify almost everything |
| `roles/iam.securityAdmin`, `roles/resourcemanager.projectIamAdmin` | Can grant any role, including to themselves |
| `roles/iam.serviceAccountTokenCreator` | Mint tokens as the service account (impersonation) |
| `roles/iam.serviceAccountUser` | Attach the SA to a VM/function and act as it |
| `roles/iam.serviceAccountKeyAdmin` | Create keys for service accounts |
| `roles/cloudfunctions.developer`, `roles/run.developer` + SA user | Deploy code that runs as a privileged SA |

```bash
gcloud iam roles describe roles/editor --format="value(includedPermissions)" | tr ';' '\n' | wc -l
gcloud iam roles list --project=<PROJECT_ID>        # custom roles
```

## 3. Service accounts and keys

```bash
gcloud iam service-accounts list --project=<PROJECT_ID>
gcloud iam service-accounts keys list --iam-account=<sa>@<PROJECT_ID>.iam.gserviceaccount.com \
  --managed-by=user --format="table(name.basename(), validAfterTime, validBeforeTime, disabled)"
gcloud iam service-accounts get-iam-policy <sa>@<PROJECT_ID>.iam.gserviceaccount.com   # who can act as it
```

`--managed-by=user` lists downloadable keys; Google-managed keys rotate automatically and are not a risk. Default service accounts (`<number>-compute@developer.gserviceaccount.com`) often still hold **Editor** on older projects.

```bash
# change: remove the Editor grant from the default compute SA
gcloud projects remove-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:<PROJECT_NUMBER>-compute@developer.gserviceaccount.com" --role=roles/editor
```

## 4. Policy Analyzer

Answers "who can do X on Y?" with inheritance and group membership resolved:

```bash
gcloud asset analyze-iam-policy --organization=<ORG_ID> \
  --full-resource-name="//cloudresourcemanager.googleapis.com/projects/<PROJECT_ID>" \
  --permissions="resourcemanager.projects.setIamPolicy" --expand-groups

gcloud asset analyze-iam-policy --organization=<ORG_ID> \
  --identity="user:alice@example.com" --expand-resources --format=json
```

## 5. Unused and excess permissions

```bash
gcloud recommender recommendations list --project=<PROJECT_ID> --location=global \
  --recommender=google.iam.policy.Recommender \
  --format="table(content.overview.member, content.overview.removedRole, content.overview.addedRoles)"
gcloud recommender insights list --project=<PROJECT_ID> --location=global \
  --insight-type=google.iam.serviceAccount.Insight      # service accounts unused for 90 days
```

## 6. Python: list user-managed keys older than 90 days

```python
from datetime import datetime, timedelta, timezone
from googleapiclient import discovery   # pip install google-api-python-client

iam = discovery.build("iam", "v1")
project = "prod-app-123"
cutoff = datetime.now(timezone.utc) - timedelta(days=90)
sas = iam.projects().serviceAccounts().list(name=f"projects/{project}").execute().get("accounts", [])
for sa in sas:
    keys = iam.projects().serviceAccounts().keys().list(
        name=sa["name"], keyTypes="USER_MANAGED").execute().get("keys", [])
    for k in keys:
        created = datetime.fromisoformat(k["validAfterTime"].replace("Z", "+00:00"))
        if created < cutoff:
            print(sa["email"], k["name"].split("/")[-1], created.date())
```

## 7. Baseline

- Grant roles to **groups**, not users; no basic roles in production.
- Block SA key creation (`iam.disableServiceAccountKeyCreation`) and use impersonation or Workload Identity Federation.
- Restrict principals to your domain (`iam.allowedPolicyMemberDomains`) ([Policy & governance](policy-governance.md)).
- Turn on **Data Access** logs for IAM so token minting is visible ([Audit logging](audit-logging.md#3-turn-on-data-access-logs)).

## Related

- [CLI & authentication](cli-authentication.md)
- [Persistence & threat hunting](persistence-hunting.md)
- [Concept: identity and access management](../../fundamentals/concepts/identity-access-management.md)

## Sources

- [IAM overview](https://cloud.google.com/iam/docs/overview)
- [Best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
- [Policy Analyzer](https://cloud.google.com/policy-intelligence/docs/policy-analyzer-overview)
- [Role recommendations](https://cloud.google.com/policy-intelligence/docs/role-recommendations-overview)
