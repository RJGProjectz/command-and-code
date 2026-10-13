---
title: Google Cloud Storage (Buckets & Data Exposure)
platforms: [GCP]
languages: [Bash, Python]
tasks: [Administration, Hardening, Investigation, Assurance]
category: Storage
tags: [gcp, cloud storage, gcs, buckets, uniform bucket-level access, public access prevention, allusers, signed urls, hmac keys, retention]
aliases: [gcloud storage ls, gsutil iam get, gcp public bucket, gcs allUsers, gcp public access prevention, gcloud storage buckets update uniform-bucket-level-access]
difficulty: intermediate
verified: true
last_verified: 2026-10-12
---

# Google Cloud Storage (Buckets & Data Exposure)

Access to a bucket comes from **IAM** (bucket, project, folder, org) and, unless **uniform bucket-level access** is on, from per-object **ACLs**. A bucket is public when `allUsers` or `allAuthenticatedUsers` holds any role. Use `gcloud storage` (the successor of `gsutil`).

!!! warning "Before you run anything"
    Every command was checked against the gcloud CLI reference (2026-10-12); this guide does not run them against a live project. Commands that change state are marked **change**.

## 1. Inventory

```bash
gcloud storage buckets list --format="table(name, location, storage_class, uniform_bucket_level_access, public_access_prevention, retention_policy.retentionPeriod)"
gcloud storage buckets describe gs://<bucket> --format=json
gcloud storage du -s gs://<bucket>                 # total size
gcloud storage ls -l "gs://<bucket>/**" | tail -n 5
```

## 2. Find exposed buckets

```bash
gcloud asset search-all-iam-policies --scope=organizations/<ORG_ID> \
  --asset-types=storage.googleapis.com/Bucket \
  --query="policy:(allUsers OR allAuthenticatedUsers)" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"

gcloud storage buckets get-iam-policy gs://<bucket> --format=json
gcloud storage objects describe gs://<bucket>/<object> --format="yaml(acl)"   # fine-grained buckets only
```

`allAuthenticatedUsers` means **any Google account in the world**, not your organization. Security Command Center reports these as `PUBLIC_BUCKET_ACL` ([Security posture](security-posture.md)).

```bash
# change: remove public access
gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allUsers --role=roles/storage.objectViewer
gcloud storage buckets update gs://<bucket> --public-access-prevention
gcloud storage buckets update gs://<bucket> --uniform-bucket-level-access
```

Enforce for the whole organization with the constraints `storage.publicAccessPrevention` and `storage.uniformBucketLevelAccess`.

## 3. Other ways data leaks

| Path | Check |
| :--- | :--- |
| **Signed URLs** | Valid up to 7 days, signed by a SA key or `signBlob`; revoke by deleting the key or removing the signer's access |
| **HMAC keys** (S3-compatible API) | `gcloud storage hmac list` — long-lived secrets tied to a service account |
| Cross-project IAM | Bindings for service accounts of other projects |
| Bucket notifications / transfer jobs | `gcloud storage buckets notifications list gs://<b>`; `gcloud transfer jobs list` |

```bash
gcloud storage hmac list --format="table(accessId, serviceAccountEmail, state, timeCreated)"
# change: deactivate then delete an HMAC key
gcloud storage hmac update <ACCESS_ID> --deactivate
```

## 4. Who read or copied objects?

Object reads are **Data Access** logs, off by default for Cloud Storage. Turn on `DATA_READ` for `storage.googleapis.com` on sensitive projects ([Audit logging](audit-logging.md#3-turn-on-data-access-logs)), then:

```bash
gcloud logging read 'resource.type="gcs_bucket" AND resource.labels.bucket_name="<bucket>"
  AND protoPayload.methodName="storage.objects.get"' --freshness=7d --limit=100 \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp, protoPayload.resourceName)"
```

Public (`allUsers`) reads are logged without a principal. For large buckets, **usage logs** or a BigQuery sink are cheaper.

## 5. Protect against deletion and ransomware

```bash
gcloud storage buckets update gs://<bucket> --versioning                    # change
gcloud storage buckets update gs://<bucket> --soft-delete-duration=30d      # change
gcloud storage buckets update gs://<bucket> --retention-period=90d          # change; lock only after testing
gcloud storage ls -a gs://<bucket>/<prefix>                                 # list noncurrent versions
gcloud storage ls --soft-deleted gs://<bucket>/**
```

A **locked** retention policy cannot be shortened or removed, even by the owner. Use it for log and evidence buckets.

## 6. Python: buckets without public access prevention

```python
from google.cloud import storage   # pip install google-cloud-storage

client = storage.Client(project="prod-app-123")
for b in client.list_buckets():
    b.reload()
    iam = b.iam_configuration
    if iam.public_access_prevention != "enforced" or not iam.uniform_bucket_level_access_enabled:
        print(b.name, iam.public_access_prevention, iam.uniform_bucket_level_access_enabled)
```

## Related

- [Keys & secrets (CMEK)](keys-secrets.md)
- [Incident response](incident-response.md)
- [Detection: CI/CD secret leak](../../detection/sigma/cicd-secret-leak.md)

## Sources

- [Public access prevention](https://cloud.google.com/storage/docs/public-access-prevention)
- [Uniform bucket-level access](https://cloud.google.com/storage/docs/uniform-bucket-level-access)
- [gcloud storage commands](https://cloud.google.com/sdk/gcloud/reference/storage)
- [Soft delete](https://cloud.google.com/storage/docs/soft-delete)
