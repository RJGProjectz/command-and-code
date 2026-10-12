---
title: Google Cloud Resource Hierarchy & Inventory
platforms: [GCP]
languages: [Bash]
tasks: [Administration, Investigation, Assurance]
category: Inventory
tags: [gcp, organization, folders, projects, cloud asset inventory, labels, tags, resource manager]
aliases: [gcloud projects list, gcloud resource-manager folders list, gcloud asset search-all-resources, gcp list all resources, gcp organization id, gcp asset inventory export]
difficulty: basic
verified: false
---

# Google Cloud Resource Hierarchy & Inventory

Google Cloud resources sit in a tree: **Organization → Folders → Projects → resources**. IAM policies and Organization Policies set at a node are **inherited** by everything below it. Most APIs work per project; **Cloud Asset Inventory** searches the whole organization at once.

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Map the tree

```bash
gcloud organizations list                          # ORG_ID and domain
gcloud resource-manager folders list --organization=<ORG_ID>
gcloud resource-manager folders list --folder=<FOLDER_ID>
gcloud projects list --format="table(projectId, projectNumber, parent.type, parent.id, lifecycleState)"
gcloud projects get-ancestors <PROJECT_ID>          # project → folders → organization
```

Projects have three identifiers: **project ID** (chosen, permanent), **project number** (appears in service-agent emails and some logs) and a display name. Translate a number with `gcloud projects describe <NUMBER> --format="value(projectId)"`.

## 2. Search every resource (Cloud Asset Inventory)

```bash
gcloud asset search-all-resources --scope=organizations/<ORG_ID> \
  --asset-types="compute.googleapis.com/Instance" \
  --format="table(name.basename(), location, project, state)"

gcloud asset search-all-resources --scope=organizations/<ORG_ID> --query="labels.env:prod"
gcloud asset search-all-resources --scope=organizations/<ORG_ID> --query="createTime>2026-10-01"
gcloud asset search-all-resources --scope=organizations/<ORG_ID> \
  --asset-types="storage.googleapis.com/Bucket" --read-mask="name,location,labels"
```

You need `roles/cloudasset.viewer` at the scope, and the `cloudasset.googleapis.com` API enabled in the project you call from.

## 3. Search IAM bindings everywhere

```bash
gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> \
  --query="policy:user:alice@example.com"
gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> \
  --query="policy:(allUsers OR allAuthenticatedUsers)"
gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> \
  --query="policy.role.permissions:iam.serviceAccountKeys.create"
```

This is the fastest way to answer "where does this person have access?" across hundreds of projects.

## 4. Export a full snapshot

```bash
# change: writes to a bucket you own
gcloud asset export --organization=<ORG_ID> --content-type=resource \
  --output-path="gs://<evidence-bucket>/assets/$(date -u +%Y%m%dT%H%M%SZ).json"
gcloud asset export --organization=<ORG_ID> --content-type=iam-policy \
  --bigquery-table=projects/<p>/datasets/asset_inventory/tables/iam_$(date -u +%Y%m%d) --output-bigquery-force
```

Export to BigQuery to diff two snapshots with SQL. `gcloud asset list --snapshot-time` and asset **feeds** (Pub/Sub on change) cover history and live alerting.

## 5. Asset history

```bash
gcloud asset get-history --project=<PROJECT_ID> --content-type=resource \
  --asset-names="//compute.googleapis.com/projects/<PROJECT_ID>/zones/<zone>/instances/<vm>" \
  --start-time=2026-10-01T00:00:00Z
```

History covers the last 35 days and shows each configuration version, useful when the audit log does not include the full resource state.

## 6. Labels vs tags

| | Labels | Tags |
| :--- | :--- | :--- |
| Purpose | Billing, filtering, search | Policy: IAM conditions, Org Policy conditions, firewall policies |
| Defined | Free-form on each resource | Centrally, at org or project (`tagKeys`, `tagValues`) |
| Inherited | No | Yes, down the hierarchy |

```bash
gcloud resource-manager tags keys list --parent=organizations/<ORG_ID>
gcloud resource-manager tags bindings list --parent=//cloudresourcemanager.googleapis.com/projects/<PROJECT_NUMBER>
```

## Related

- [Identity & access (Cloud IAM)](identity-access.md)
- [Policy & governance](policy-governance.md)
- [Concept: cloud-native security](../../fundamentals/concepts/cloud-native-security.md)

## Sources

- [Resource hierarchy](https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy)
- [Cloud Asset Inventory: search resources](https://cloud.google.com/asset-inventory/docs/searching-resources)
- [Search IAM policies](https://cloud.google.com/asset-inventory/docs/searching-iam-policies)
- [Tags overview](https://cloud.google.com/resource-manager/docs/tags/tags-overview)
