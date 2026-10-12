---
title: Google Cloud Logging & BigQuery Log Queries
platforms: [GCP]
languages: [Bash]
tasks: [Investigation, Troubleshooting, Detection Engineering, Administration]
category: Logging
tags: [gcp, cloud logging, logging query language, logs explorer, log analytics, bigquery, log-based metrics, alerting, cloud monitoring]
aliases: [gcp logging query language examples, gcloud logging read filter, gcp log analytics sql, bigquery audit log query, gcp log based metric alert, logs explorer query]
difficulty: intermediate
verified: false
---

# Google Cloud Logging & BigQuery Log Queries

Cloud Logging stores logs in **log buckets** (`_Required`, `_Default`, plus any you create). Query them three ways:

| Tool | Language | Best for |
| :--- | :--- | :--- |
| **Logs Explorer** / `gcloud logging read` | Logging query language (filters) | Finding events fast |
| **Log Analytics** | SQL (BigQuery dialect) over an upgraded log bucket | Aggregation without exporting |
| **BigQuery** via a sink | SQL | Long retention, joins, large volumes |

!!! danger "VERIFY BEFORE PRODUCTION USE"
    Written from Google Cloud documentation and not yet lab-tested in this repo. Commands that change state are marked **change**.

## 1. Logging query language

| Pattern | Meaning |
| :--- | :--- |
| `field="value"` / `field!="value"` | Equals / not equals |
| `field:"text"` | Has (substring, case-insensitive) |
| `field=~"regex"` | Regular expression |
| `field:*` | Field exists |
| `AND`, `OR`, `NOT`, `( )` | Boolean; unlike SQL, `OR` binds tighter than `AND`, so use brackets |
| `log_id("cloudaudit.googleapis.com/activity")` | Select a log |
| `timestamp>="2026-10-01T00:00:00Z"` | Time bound (or `--freshness` on the CLI) |
| `severity>=ERROR` | Severity threshold |

```bash
gcloud logging read 'resource.type="gce_instance" AND severity>=ERROR' --freshness=1h --limit=20
gcloud logging read 'protoPayload.status.code=7' --freshness=1d \
  --format="table(timestamp, protoPayload.authenticationInfo.principalEmail, protoPayload.methodName)"
gcloud logging logs list                            # which logs exist in this project
```

## 2. Useful filters

```text
-- Failed or denied API calls
log_id("cloudaudit.googleapis.com/activity") AND protoPayload.status.code!=0

-- Calls made with a service-account key (not impersonation or metadata tokens)
protoPayload.authenticationInfo.serviceAccountKeyName:*

-- Everything from one source IP (console sign-ins themselves are in Workspace logs)
protoPayload.requestMetadata.callerIp="203.0.113.10"

-- Firewall rule changes
resource.type="gce_firewall_rule" AND log_id("cloudaudit.googleapis.com/activity")

-- GKE: exec into pods
resource.type="k8s_cluster" AND protoPayload.methodName="io.k8s.core.v1.pods.exec.create"
```

## 3. Log Analytics (SQL without exporting)

```bash
# change: upgrade a bucket and link a BigQuery dataset
gcloud logging buckets update org-audit --location=global --enable-analytics
gcloud logging links create org_audit_link --bucket=org-audit --location=global
```

```sql
SELECT
  proto_payload.audit_log.authentication_info.principal_email AS principal,
  proto_payload.audit_log.method_name AS method,
  COUNT(*) AS calls
FROM `<LOG_PROJECT>.global.org-audit._AllLogs`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
  AND log_id = "cloudaudit.googleapis.com/activity"
GROUP BY principal, method
ORDER BY calls DESC
LIMIT 50;
```

## 4. BigQuery log sinks

```bash
# change: org-wide audit logs into BigQuery, partitioned tables
bq --location=US mk --dataset <LOG_PROJECT>:audit_logs
gcloud logging sinks create audit-to-bq bigquery.googleapis.com/projects/<LOG_PROJECT>/datasets/audit_logs \
  --organization=<ORG_ID> --include-children --use-partitioned-tables \
  --log-filter='log_id("cloudaudit.googleapis.com/activity") OR log_id("cloudaudit.googleapis.com/data_access")'
```

Tables are named after the log, for example `cloudaudit_googleapis_com_activity`:

```sql
SELECT timestamp,
       protopayload_auditlog.authenticationInfo.principalEmail AS principal,
       protopayload_auditlog.requestMetadata.callerIp AS ip,
       protopayload_auditlog.methodName AS method,
       protopayload_auditlog.resourceName AS resource
FROM `<LOG_PROJECT>.audit_logs.cloudaudit_googleapis_com_activity`
WHERE DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
  AND protopayload_auditlog.methodName LIKE '%SetIamPolicy%'
ORDER BY timestamp DESC;
```

Always filter on the partition (`DATE(timestamp)` or `_PARTITIONTIME`) to keep query cost down.

## 5. Log-based metrics and alerts

```bash
# change: count IAM policy changes, then alert on any
gcloud logging metrics create iam-policy-changes \
  --description="SetIamPolicy calls" \
  --log-filter='protoPayload.methodName="SetIamPolicy" AND log_id("cloudaudit.googleapis.com/activity")'
gcloud logging metrics list
```

Create the alerting policy on `logging.googleapis.com/user/iam-policy-changes` in Cloud Monitoring, or use a **log-based alert** directly from a Logs Explorer query. CIS Benchmark recommends metrics for: IAM changes, custom role changes, firewall changes, route changes, VPC changes, Cloud Storage IAM changes, SQL instance config changes, and audit config changes.

## 6. Retention and cost

```bash
gcloud logging buckets list --format="table(name.basename(), location, retentionDays, locked, analyticsEnabled)"
gcloud logging buckets update _Default --location=global --retention-days=90   # change
gcloud logging sinks list
```

## Related

- [Audit logging](audit-logging.md)
- [Detection: SPL index](../../detection/spl/index.md)
- [Task: hypothesis-driven hunting](../../tasks/threat-hunting/hypothesis-driven-hunting-framework.md)

## Sources

- [Logging query language](https://cloud.google.com/logging/docs/view/logging-query-language)
- [Log Analytics](https://cloud.google.com/logging/docs/log-analytics)
- [BigQuery schema for logs](https://cloud.google.com/logging/docs/export/bigquery)
- [Log-based metrics](https://cloud.google.com/logging/docs/logs-based-metrics)
