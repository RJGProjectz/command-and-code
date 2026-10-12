---
title: Google Cloud Audit Logs
platforms: [GCP]
languages: [Bash]
tasks: [Investigation, Incident Response, Forensics, Hardening]
category: Logging
tags: [gcp, cloud audit logs, admin activity, data access, system event, policy denied, log sinks, aggregated sinks, log buckets]
aliases: [gcp who deleted vm, gcloud logging read audit, gcp data access logs enable, gcp aggregated log sink, cloudaudit.googleapis.com activity, gcp log retention]
difficulty: intermediate
verified: false
---

# Google Cloud Audit Logs

Cloud Audit Logs write four logs per project, folder and organization:

| Log | Records | Default | Retention in `_Required` / `_Default` |
| :--- | :--- | :--- | :--- |
| **Admin Activity** (`activity`) | Config and metadata changes (create, delete, setIamPolicy) | Always on, free | 400 days |
| **System Event** (`system_event`) | Google-initiated changes (live migration, autoscaling) | Always on, free | 400 days |
| **Data Access** (`data_access`) | Reads of config and data (`ADMIN_READ`, `DATA_READ`, `DATA_WRITE`) | **Off** (except BigQuery) | 30 days |
| **Policy Denied** (`policy`) | Requests blocked by VPC Service Controls or Org Policy | On | 30 days |

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Quick lookups

```bash
# Who deleted a VM?
gcloud logging read 'log_id("cloudaudit.googleapis.com/activity")
  AND protoPayload.methodName:"compute.instances.delete"' --project=<PROJECT_ID> --freshness=30d \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.requestMetadata.callerIp, protoPayload.resourceName)"

# Everything one identity did
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="alice@example.com"' --freshness=7d --limit=200

# IAM changes at the organization
gcloud logging read 'protoPayload.methodName="SetIamPolicy"' --organization=<ORG_ID> --freshness=14d
```

`gcloud logging read` searches one project unless you pass `--organization` or `--folder` (which only reads logs stored at that level, not project logs; use an [aggregated sink](#4-aggregated-sinks) for that).

## 2. Read an audit entry

| Field | Meaning |
| :--- | :--- |
| `protoPayload.authenticationInfo.principalEmail` | Caller (user or service account) |
| `protoPayload.authenticationInfo.serviceAccountDelegationInfo` | Impersonation chain |
| `protoPayload.authenticationInfo.serviceAccountKeyName` | Which SA key was used, if any |
| `protoPayload.requestMetadata.callerIp` / `callerSuppliedUserAgent` | Source IP and tool |
| `protoPayload.methodName`, `resourceName` | What was called, on what |
| `protoPayload.status.code` | `0` or absent = success; `7` = permission denied |
| `protoPayload.authorizationInfo[].granted` | Which permission was checked |

## 3. Turn on Data Access logs

Data Access logs are configured in the IAM policy's `auditConfigs`. Set them at the organization so every project inherits them.

```bash
gcloud organizations get-iam-policy <ORG_ID> --format=json > org-policy.json
# edit: add to org-policy.json
#  "auditConfigs": [
#    {"service": "allServices", "auditLogConfigs": [{"logType": "ADMIN_READ"}]},
#    {"service": "iam.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]},
#    {"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}, {"logType": "DATA_WRITE"}]},
#    {"service": "secretmanager.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]
gcloud organizations set-iam-policy <ORG_ID> org-policy.json      # change
```

Keep the `etag` from the read so a concurrent change is not overwritten. `DATA_READ` on Cloud Storage can be very large; scope it to sensitive projects if cost matters.

## 4. Aggregated sinks

Send every project's audit logs to one place the project owners cannot delete:

```bash
# change: org-level sink to a log bucket in a dedicated logging project
gcloud logging buckets create org-audit --location=global --retention-days=730 --project=<LOG_PROJECT>
gcloud logging sinks create org-audit-sink \
  logging.googleapis.com/projects/<LOG_PROJECT>/locations/global/buckets/org-audit \
  --organization=<ORG_ID> --include-children \
  --log-filter='log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/data_access") OR log_id("cloudaudit.googleapis.com/policy")'
gcloud logging sinks describe org-audit-sink --organization=<ORG_ID> --format="value(writerIdentity)"
```

Grant the sink's `writerIdentity` write access at the destination. Lock long-term buckets with `gcloud logging buckets update org-audit --location=global --locked` once retention is right. Sink destinations: log bucket, BigQuery, Cloud Storage, Pub/Sub (SIEM).

## 5. Tampering to watch for

```bash
gcloud logging read 'protoPayload.methodName:("DeleteSink" OR "UpdateSink" OR "DeleteBucket" OR "UpdateBucket" OR "DeleteExclusion" OR "CreateExclusion")
  AND protoPayload.serviceName="logging.googleapis.com"' --organization=<ORG_ID> --freshness=30d

gcloud logging read 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*' --freshness=30d
```

Admin Activity logs and the `_Required` bucket cannot be disabled or deleted, but sinks, exclusions on `_Default` and Data Access settings can.

## Related

- [Monitoring & log queries](monitoring-logs.md)
- [Persistence & threat hunting](persistence-hunting.md)
- [Concept: digital forensics](../../fundamentals/concepts/digital-forensics.md)

## Sources

- [Cloud Audit Logs overview](https://cloud.google.com/logging/docs/audit)
- [Configure Data Access audit logs](https://cloud.google.com/logging/docs/audit/configure-data-access)
- [Aggregated sinks](https://cloud.google.com/logging/docs/export/aggregated_sinks)
- [Understanding audit logs](https://cloud.google.com/logging/docs/audit/understanding-audit-logs)
